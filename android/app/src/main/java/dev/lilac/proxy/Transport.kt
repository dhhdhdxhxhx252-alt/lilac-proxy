package dev.lilac.proxy

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

const val WS_PATH = "/apiws"
private val CLOSED_SENTINEL = ByteArray(0)

/** Канал до DC: один интерфейс для WebSocket и для TCP fallback. */
interface Transport : AutoCloseable {
    val description: String
    fun send(data: ByteArray): Boolean

    /** null — канал закрыт или долго молчал. */
    fun receive(): ByteArray?
    override fun close()
}

/**
 * Прямое TCP-соединение с DC на 443 без TLS: поверх него идёт obfs2-поток.
 */
class TcpTransport(host: String, port: Int = 443, connectTimeoutMs: Int = 10_000) : Transport {
    private val socket = Socket()
    private val input: InputStream
    private val output: OutputStream
    private val buffer = ByteArray(CHUNK)

    override val description = "tcp $host:$port"

    init {
        socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
        socket.tcpNoDelay = true
        input = socket.getInputStream()
        output = socket.getOutputStream()
    }

    override fun send(data: ByteArray): Boolean = try {
        output.write(data)
        output.flush()
        true
    } catch (error: IOException) {
        false
    }

    override fun receive(): ByteArray? = try {
        val read = input.read(buffer)
        if (read <= 0) null else buffer.copyOfRange(0, read)
    } catch (error: IOException) {
        null
    }

    override fun close() {
        runCatching { socket.close() }
    }

    private companion object {
        const val CHUNK = 16 * 1024
    }
}

/**
 * WebSocket до шлюза Telegram Web: каждое MTProto-сообщение уходит отдельным бинарным фреймом.
 */
class WsTransport(
    private val client: OkHttpClient,
    private val domain: String,
    private val openTimeoutMs: Long = 10_000,
) : Transport {
    private val inbox = LinkedBlockingQueue<ByteArray>()
    private val opened = CountDownLatch(1)
    private var webSocket: WebSocket? = null

    @Volatile
    var failure: String? = null
        private set

    override val description = "wss://$domain$WS_PATH"

    /** Ждёт onOpen/onFailure. false — канал не поднялся, причину видно в [failure]. */
    fun connect(): Boolean {
        val request = Request.Builder()
            .url("wss://$domain$WS_PATH")
            .header("Sec-WebSocket-Protocol", "binary")
            .build()
        webSocket = client.newWebSocket(request, listener)
        if (!opened.await(openTimeoutMs, TimeUnit.MILLISECONDS)) {
            failure = "таймаут рукопожатия"
            close()
            return false
        }
        return failure == null
    }

    override fun send(data: ByteArray): Boolean =
        webSocket?.send(data.toByteString()) ?: false

    override fun receive(): ByteArray? {
        val next = inbox.poll(IDLE_TIMEOUT_SECONDS, TimeUnit.SECONDS) ?: return null
        return if (next === CLOSED_SENTINEL) null else next
    }

    override fun close() {
        webSocket?.close(1000, null)
        webSocket?.cancel()
        webSocket = null
        inbox.clear()
        // будит поток, застрявший в receive()
        inbox.put(CLOSED_SENTINEL)
    }

    private val listener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            opened.countDown()
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            inbox.put(bytes.toByteArray())
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(1000, null)
            opened.countDown()
            inbox.put(CLOSED_SENTINEL)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            failure = "${t.javaClass.simpleName}: ${t.message}"
            opened.countDown()
            inbox.put(CLOSED_SENTINEL)
        }
    }

    private companion object {
        const val IDLE_TIMEOUT_SECONDS = 60L
    }
}
