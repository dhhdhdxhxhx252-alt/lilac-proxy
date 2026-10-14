//
//  Settings.swift + ProxyController.swift
//  Хранилище настроек и управление жизненным циклом прокси.
//

import Foundation
import SwiftUI

/// Снимок настроек на момент запуска прокси.
struct ProxyConfig {
    let secret: Data
    let port: Int
    let dcOverrides: [Int: String]
    let preferWs: Bool
    let tcpFallback: Bool
}

final class Settings: ObservableObject {
    private enum Key {
        static let secret = "lilac.secret"
        static let port = "lilac.port"
        static let preferWs = "lilac.prefer_ws"
        static let tcpFallback = "lilac.tcp_fallback"
        static let dcTargets = "lilac.dc_targets"
    }

    static let defaultPort = 1443

    @Published var secretHex: String {
        didSet { defaults.set(secretHex, forKey: Key.secret) }
    }

    @Published var port: Int {
        didSet { defaults.set(port, forKey: Key.port) }
    }

    @Published var preferWs: Bool {
        didSet { defaults.set(preferWs, forKey: Key.preferWs) }
    }

    @Published var tcpFallback: Bool {
        didSet { defaults.set(tcpFallback, forKey: Key.tcpFallback) }
    }

    /// Ключи — номера DC; для медиа-адреса используется отрицательный номер.
    @Published var dcTargets: [Int: String] {
        didSet {
            let encoded = dcTargets.mapValues { $0 }
            defaults.set(encoded.map { "\($0.key)|\($0.value)" }.sorted(), forKey: Key.dcTargets)
        }
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        secretHex = defaults.string(forKey: Key.secret) ?? Settings.randomSecretHex()
        port = defaults.object(forKey: Key.port) as? Int ?? Settings.defaultPort
        preferWs = defaults.object(forKey: Key.preferWs) as? Bool ?? true
        tcpFallback = defaults.object(forKey: Key.tcpFallback) as? Bool ?? true
        dcTargets = (defaults.stringArray(forKey: Key.dcTargets) ?? []).reduce(into: [Int: String]()) { acc, raw in
            let parts = raw.split(separator: "|", maxSplits: 1)
            guard parts.count == 2, let dc = Int(parts[0]) else { return }
            acc[dc] = String(parts[1])
        }
    }

    static func randomSecretHex() -> String {
        Obfs2.hex(Obfs2.randomBytes(16))
    }

    func config() -> ProxyConfig? {
        guard let secret = Obfs2.parseSecret(secretHex) else { return nil }
        guard port >= 1024, port <= 65535 else { return nil }
        return ProxyConfig(secret: secret, port: port, dcOverrides: dcTargets,
                           preferWs: preferWs, tcpFallback: tcpFallback)
    }
}

@MainActor
final class ProxyController: ObservableObject {
    @Published var running = false
    @Published var errorMessage: String?
    @Published private(set) var stats = ProxyStats()
    @Published private(set) var log = LogStore()

    private var server: ProxyServer?
    private var timer: Timer?

    func toggle(settings: Settings) {
        if running {
            stop()
            return
        }
        guard let config = settings.config() else {
            errorMessage = "Проверьте секрет (32 hex) и порт 1024–65535"
            return
        }
        start(config: config)
    }

    private func start(config: ProxyConfig) {
        let instance = ProxyServer(config: config, stats: stats, log: log)
        do {
            try instance.start()
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        server = instance
        running = true
        errorMessage = nil
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            Task { @MainActor in self.objectWillChange.send() }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        server?.stop()
        server = nil
        running = false
    }

    func stat(_ key: String) -> Int64 { stats.value(key) }
}
