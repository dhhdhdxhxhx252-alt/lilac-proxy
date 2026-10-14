package dev.lilac.proxy

import okhttp3.OkHttpClient
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

private const val BRIDGE_CHUNK = 16 * 1024
private val HTTP_NOT_FOUND = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".toByteArray()

/**
 * Локальный MTProto-прокси: принимает соединение Telegram на 127.0.0.1, перешифровывает
 * obfs2-потоки и передаёт трафик дальше по WebSocket (или TCP) до дата-центра.
 */
class ProxyServer(
    private val config: ProxyConfig,
    private val stats: ProxyStats,
    private val log: LogStore,
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)
        .pingInterval(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build()

    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private val connections = CopyOnWriteArrayList<ConnectionThread>()

    @Volatile
    private var running = false

    val boundPort: Int get() = serverSocket?.localPort ?: -1

    fun start() {
        check(!running) { "Прокси уже запущен" }
        val listener = ServerSocket()
        listener.reuseAddress = true
        listener.bind(InetSocketAddress("127.0.0.1", config.port))
        serverSocket = listener
        running = true
        acceptThread = thread("lilac-accept") { acceptLoop(listener) }
        log.add("Слушаю 127.0.0.1:${listener.localPort}")
    }

    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        connections.forEach { connection -> connection.shutdown() }
        connections.clear()
        acceptThread?.interrupt()
        acceptThread = null
        client.dispatcher.executorService.shutdownNow()
        client.connectionPool.evictAll()
    }

    private fun acceptLoop(listener: ServerSocket) {
        while (running) {
            val socket = try {
                listener.accept()
            } catch (error: IOException) {
                break
            }
            val connection = ConnectionThread(socket)
            connections.add(connection)
            connection.start()
        }
    }

    /** Одна сессия Telegram: handshake, выбор транспорта, бридж в обе стороны. */
    private inner class ConnectionThread(private val socket: Socket) : Thread("lilac-conn") {

        override fun run() {
            try {
                bridgeClient()
            } catch (error: IOException) {
                // обрыв соединения клиента — штатная ситуация
            } finally {
                connections.remove(this)
                shutdown()
            }
        }

        fun shutdown() {
            runCatching { socket.close() }
        }

        private fun bridgeClient() {
            socket.tcpNoDelay = true
            socket.soTimeout = IDLE_TIMEOUT_MS
            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            val raw = ByteArray(Obfs2.HANDSHAKE_SIZE)
            if (!readFully(input, raw)) return
            if (Handshake.isHttpTransport(raw)) {
                stats.connectionsBad.incrementAndGet()
                runCatching { output.write(HTTP_NOT_FOUND) }
                return
            }

            val clientDecryptor = Obfs2.clientDecryptor(raw, config.secret)
            val plain = raw.copyOf()
            clientDecryptor.xor(plain)
            val info = Handshake.clientInit(plain)
            if (info == null) {
                stats.connectionsBad.incrementAndGet()
                log.add("Отклонено: init не расшифровался (проверьте секрет)")
                return
            }

            val relayInit = Handshake.relayInit(info.proto, info.dc, info.isMedia)
            val clientEncryptor = Obfs2.clientEncryptor(raw, config.secret)
            // поток DC стартует после 64 байт relay-init, как и MsgSplitter
            val relayEncryptor = Obfs2.relayEncryptor(relayInit)
                .apply { xor(ByteArray(Obfs2.HANDSHAKE_SIZE)) }
            val relayDecryptor = Obfs2.relayDecryptor(relayInit)
            val splitter = MsgSplitter(relayInit, info.proto)

            val remote = openTransport(info, relayInit) ?: return
            stats.connectionsActive.incrementAndGet()
            log.add("${info.tag} → ${remote.description}")

            val up = thread("lilac-up") {
                try {
                    pumpUp(input, remote, clientDecryptor, relayEncryptor, splitter)
                } catch (error: IOException) {
                    Unit
                } finally {
                    remote.close()
                    shutdown()
                }
            }
            val down = thread("lilac-down") {
                try {
                    pumpDown(remote, relayDecryptor, clientEncryptor, output)
                } catch (error: IOException) {
                    Unit
                } finally {
                    remote.close()
                    shutdown()
                }
            }
            up.join()
            down.join()
        }
    }

    private fun pumpUp(
        input: InputStream,
        remote: Transport,
        clientDecryptor: AesCtrStream,
        relayEncryptor: AesCtrStream,
        splitter: MsgSplitter,
    ) {
        val buffer = ByteArray(BRIDGE_CHUNK)
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) {
                splitter.flush().forEach { part -> remote.send(part) }
                return
            }
            clientDecryptor.xor(buffer, 0, read)
            relayEncryptor.xor(buffer, 0, read)
            stats.bytesUp.addAndGet(read.toLong())
            for (part in splitter.split(buffer, 0, read)) {
                if (!remote.send(part)) return
            }
        }
    }

    private fun pumpDown(
        remote: Transport,
        relayDecryptor: AesCtrStream,
        clientEncryptor: AesCtrStream,
        output: OutputStream,
    ) {
        while (true) {
            val data = remote.receive() ?: return
            relayDecryptor.xor(data)
            clientEncryptor.xor(data)
            output.write(data)
            output.flush()
            stats.bytesDown.addAndGet(data.size.toLong())
        }
    }

    /** WS до шлюза Telegram Web, при отказе — прямое TCP-подключение к DC. */
    private fun openTransport(info: ClientInit, relayInit: ByteArray): Transport? {
        if (config.preferWs) {
            for (domain in Targets.wsDomains(info.dc, info.isMedia)) {
                val ws = WsTransport(client, domain)
                if (!ws.connect()) {
                    stats.lastError = "$domain: ${ws.failure}"
                    continue
                }
                if (!ws.send(relayInit)) {
                    ws.close()
                    stats.lastError = "$domain: не удалось отправить init"
                    continue
                }
                stats.connectionsWs.incrementAndGet()
                return ws
            }
            log.add("${info.tag} WS недоступен (${stats.lastError}), ищу обход")
        }

        if (!config.tcpFallback) return null
        val host = Targets.configuredTarget(config.dcOverrides, info.dc, info.isMedia)
            ?: Targets.fallbackIp(info.dc)
        if (host == null) {
            log.add("${info.tag}: нет адреса DC в списке fallback")
            return null
        }
        return try {
            val tcp = TcpTransport(host)
            if (!tcp.send(relayInit)) {
                tcp.close()
                null
            } else {
                stats.connectionsTcp.incrementAndGet()
                tcp
            }
        } catch (error: IOException) {
            stats.lastError = "${error.javaClass.simpleName}: ${error.message}"
            log.add("${info.tag} TCP к $host не поднялся: ${error.message}")
            null
        }
    }

    private fun readFully(input: InputStream, into: ByteArray): Boolean {
        var offset = 0
        while (offset < into.size) {
            val read = input.read(into, offset, into.size - offset)
            if (read <= 0) return false
            offset += read
        }
        return true
    }

    private fun thread(name: String, body: () -> Unit): Thread =
        Thread({ body() }, name).apply { isDaemon = true; start() }

    private companion object {
        const val IDLE_TIMEOUT_MS = 120_000
    }
}
