//
//  ProxyServer.swift
//  Локальный MTProto-прокси: принимает Telegram на 127.0.0.1, перешифровывает obfs2
//  и отдаёт трафик дальше по WebSocket или прямому TCP до дата-центра.
//

import Foundation
import Network

private let bridgeChunk = 16 * 1024
private let httpNotFound = Data("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".utf8)

/// Канал до DC: один интерфейс для WebSocket и для TCP fallback.
protocol Transport: AnyObject {
    var description: String { get }
    func start(relayInit: Data, completion: @escaping (Bool) -> Void)
    func send(_ data: Data)
    func receive(_ completion: @escaping (Data?) -> Void)
    func close()
}

/// WebSocket до шлюза Telegram Web: каждое MTProto-сообщение — отдельный бинарный фрейм.
final class WsTransport: Transport {
    private let url: URL
    private let session: URLSession
    private var task: URLSessionWebSocketTask?

    var description: String { "wss://\(url.host ?? "")\(url.path)" }

    init(domain: String, session: URLSession) {
        self.url = URL(string: "wss://\(domain)/apiws")!
        self.session = session
    }

    func start(relayInit: Data, completion: @escaping (Bool) -> Void) {
        let task = session.webSocketTask(with: url)
        task.maximumMessageSize = bridgeChunk
        self.task = task
        task.resume()
        task.send(.data(relayInit)) { error in
            completion(error == nil)
        }
    }

    func send(_ data: Data) {
        task?.send(.data(data)) { _ in }
    }

    func receive(_ completion: @escaping (Data?) -> Void) {
        task?.receive { result in
            switch result {
            case .success(let message):
                switch message {
                case .data(let data): completion(data)
                case .string(let text): completion(Data(text.utf8))
                @unknown default: completion(nil)
                }
            case .failure:
                completion(nil)
            }
        }
    }

    func close() {
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
    }
}

/// Прямое TCP-соединение с DC на 443 без TLS: поверх него идёт obfs2-поток.
final class TcpTransport: Transport {
    static let queue = DispatchQueue(label: "dev.lilac.proxy.tcp")

    private let host: String
    private let connection: NWConnection

    var description: String { "tcp \(host):443" }

    init(host: String) {
        self.host = host
        self.connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: 443),
            using: .tcp
        )
        connection.start(queue: TcpTransport.queue)
    }

    func start(relayInit: Data, completion: @escaping (Bool) -> Void) {
        var settled = false
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !settled else { return }
            switch state {
            case .ready:
                settled = true
                self.connection.send(content: relayInit, completion: .contentProcessed { error in
                    completion(error == nil)
                })
            case .failed, .cancelled:
                settled = true
                completion(false)
            default:
                break
            }
        }
    }

    func send(_ data: Data) {
        connection.send(content: data, completion: .contentProcessed { _ in })
    }

    func receive(_ completion: @escaping (Data?) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: bridgeChunk) { data, _, isComplete, error in
            if error != nil || isComplete {
                completion(nil)
                return
            }
            completion(data ?? Data())
        }
    }

    func close() {
        connection.cancel()
    }
}

final class ProxyServer {
    private let config: ProxyConfig
    private let stats: ProxyStats
    private let log: LogStore
    private let queue = DispatchQueue(label: "dev.lilac.proxy.listener")
    private var listener: NWListener?
    private var closedSessions = Set<ObjectIdentifier>()

    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.waitsForConnectivity = false
        configuration.timeoutIntervalForRequest = 30
        return URLSession(configuration: configuration)
    }()

    init(config: ProxyConfig, stats: ProxyStats, log: LogStore) {
        self.config = config
        self.stats = stats
        self.log = log
    }

    enum ProxyError: LocalizedError {
        case invalidPort

        var errorDescription: String? { "Порт вне диапазона" }
    }

    func start() throws {
        guard let port = NWEndpoint.Port(rawValue: UInt16(config.port)) else {
            throw ProxyError.invalidPort
        }
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let listener = try NWListener(using: parameters, on: port)
        listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        listener.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state {
                self?.log.add("Листенер упал: \(error.localizedDescription)")
            }
        }
        listener.start(queue: queue)
        self.listener = listener
        log.add("Слушаю 127.0.0.1:\(config.port)")
    }

    func stop() {
        listener?.cancel()
        listener = nil
        closedSessions.removeAll()
        stats.set(ProxyStats.Key.connectionsActive, 0)
    }

    private func accept(_ connection: NWConnection) {
        guard isLoopback(connection.endpoint) else {
            connection.cancel()
            return
        }
        connection.start(queue: queue)
        readHandshake(connection)
    }

    /// Прокси слушает наружу только для самого устройства: чужие подключения отклоняем.
    private func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        switch endpoint {
        case .hostPort(let host, _):
            switch host {
            case .ipv4(let address): return address == .loopback
            case .ipv6(let address): return address.description == "::1"
            case .name(let name, _): return name == "localhost"
            @unknown default: return false
            }
        default:
            return false
        }
    }

    private func readHandshake(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: Obfs2.handshakeSize,
                           maximumLength: Obfs2.handshakeSize) { [weak self] data, _, isComplete, _ in
            guard let self, let data, !isComplete else {
                connection.cancel()
                return
            }
            self.bridge(connection, raw: data)
        }
    }

    private func bridge(_ connection: NWConnection, raw: Data) {
        stats.add(ProxyStats.Key.connectionsTotal, 1)
        guard raw.count >= Obfs2.handshakeSize else {
            connection.cancel()
            return
        }
        if Handshake.isHttpTransport(raw) {
            stats.add(ProxyStats.Key.connectionsBad, 1)
            connection.send(content: httpNotFound, completion: .contentProcessed { _ in
                connection.cancel()
            })
            return
        }
        guard let clientDecryptor = Obfs2.clientDecryptor(raw, secret: config.secret) else {
            connection.cancel()
            return
        }
        var plain = raw
        guard clientDecryptor.xor(&plain), let info = Handshake.clientInit(plain) else {
            stats.add(ProxyStats.Key.connectionsBad, 1)
            log.add("Отклонено: init не расшифровался (проверьте секрет)")
            connection.cancel()
            return
        }
        guard let relayInit = Handshake.relayInit(proto: info.proto, dc: info.dc, isMedia: info.isMedia),
              let clientEncryptor = Obfs2.clientEncryptor(raw, secret: config.secret),
              let relayEncryptor = Obfs2.relayEncryptor(relayInit),
              let relayDecryptor = Obfs2.relayDecryptor(relayInit),
              let splitter = MsgSplitter(relayInit: relayInit, proto: info.proto)
        else {
            connection.cancel()
            return
        }
        // поток DC стартует после 64 байт relay-init, как и MsgSplitter
        var skip = Data(count: Obfs2.handshakeSize)
        relayEncryptor.xor(&skip)

        openTransport(info: info, relayInit: relayInit) { [weak self] transport in
            guard let self, let transport else {
                self?.stats.add(ProxyStats.Key.connectionsBad, 1)
                connection.cancel()
                return
            }
            self.stats.add(ProxyStats.Key.connectionsActive, 1)
            self.log.add("\(info.tag) → \(transport.description)")
            self.pumpDown(connection, transport: transport,
                          relayDecryptor: relayDecryptor, clientEncryptor: clientEncryptor)
            self.pumpUp(connection, transport: transport, clientDecryptor: clientDecryptor,
                        relayEncryptor: relayEncryptor, splitter: splitter)
        }
    }

    private func pumpUp(
        _ connection: NWConnection,
        transport: Transport,
        clientDecryptor: AesCtrStream,
        relayEncryptor: AesCtrStream,
        splitter: MsgSplitter
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: bridgeChunk) { [weak self] data, _, isComplete, _ in
            guard let self else { return }
            guard let data, !data.isEmpty, !isComplete else {
                splitter.flush().forEach { transport.send($0) }
                self.finish(connection, transport)
                return
            }
            self.stats.add(ProxyStats.Key.bytesUp, Int64(data.count))
            var chunk = data
            guard clientDecryptor.xor(&chunk), relayEncryptor.xor(&chunk) else {
                self.finish(connection, transport)
                return
            }
            splitter.split(chunk).forEach { transport.send($0) }
            self.pumpUp(connection, transport: transport, clientDecryptor: clientDecryptor,
                        relayEncryptor: relayEncryptor, splitter: splitter)
        }
    }

    private func pumpDown(
        _ connection: NWConnection,
        transport: Transport,
        relayDecryptor: AesCtrStream,
        clientEncryptor: AesCtrStream
    ) {
        transport.receive { [weak self] data in
            guard let self else { return }
            guard let data, !data.isEmpty else {
                self.finish(connection, transport)
                return
            }
            var chunk = data
            guard relayDecryptor.xor(&chunk), clientEncryptor.xor(&chunk) else {
                self.finish(connection, transport)
                return
            }
            self.stats.add(ProxyStats.Key.bytesDown, Int64(chunk.count))
            connection.send(content: chunk, completion: .contentProcessed { error in
                guard error == nil else {
                    self.finish(connection, transport)
                    return
                }
                self.pumpDown(connection, transport: transport,
                              relayDecryptor: relayDecryptor, clientEncryptor: clientEncryptor)
            })
        }
    }

    private func finish(_ connection: NWConnection, _ transport: Transport) {
        queue.async {
            let key = ObjectIdentifier(connection)
            guard !self.closedSessions.contains(key) else { return }
            self.closedSessions.insert(key)
            transport.close()
            connection.cancel()
            if self.stats.value(ProxyStats.Key.connectionsActive) > 0 {
                self.stats.add(ProxyStats.Key.connectionsActive, -1)
            }
        }
    }

    /// WS до шлюза Telegram Web по очереди, при отказе — прямой TCP к DC.
    private func openTransport(info: ClientInit, relayInit: Data, done: @escaping (Transport?) -> Void) {
        guard config.preferWs else {
            openTcp(info: info, relayInit: relayInit, done: done)
            return
        }
        let domains = Targets.wsDomains(dc: info.dc, isMedia: info.isMedia)
        func attempt(_ index: Int) {
            guard index < domains.count else {
                log.add("\(info.tag) WS недоступен, ищу обход")
                openTcp(info: info, relayInit: relayInit, done: done)
                return
            }
            let ws = WsTransport(domain: domains[index], session: session)
            ws.start(relayInit: relayInit) { opened in
                guard opened else {
                    ws.close()
                    attempt(index + 1)
                    return
                }
                self.stats.add(ProxyStats.Key.connectionsWs, 1)
                done(ws)
            }
        }
        attempt(0)
    }

    private func openTcp(info: ClientInit, relayInit: Data, done: @escaping (Transport?) -> Void) {
        guard config.tcpFallback else {
            done(nil)
            return
        }
        guard let host = Targets.configuredTarget(config.dcOverrides, dc: info.dc, isMedia: info.isMedia)
            ?? Targets.fallbackIp(dc: info.dc) else {
            log.add("\(info.tag): нет адреса DC в списке fallback")
            done(nil)
            return
        }
        let tcp = TcpTransport(host: host)
        tcp.start(relayInit: relayInit) { opened in
            if opened { self.stats.add(ProxyStats.Key.connectionsTcp, 1) }
            done(opened ? tcp : nil)
        }
    }
}
