package dev.lilac.proxy

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/** Счётчики трафика и состояний, которые показывает интерфейс. */
class ProxyStats {
    val connectionsTotal = AtomicLong()
    val connectionsActive = AtomicLong()
    val connectionsWs = AtomicLong()
    val connectionsTcp = AtomicLong()
    val connectionsBad = AtomicLong()
    val bytesUp = AtomicLong()
    val bytesDown = AtomicLong()
    @Volatile var lastError: String? = null

    fun reset() {
        connectionsTotal.set(0); connectionsActive.set(0); connectionsWs.set(0)
        connectionsTcp.set(0); connectionsBad.set(0); bytesUp.set(0); bytesDown.set(0)
        lastError = null
    }
}

/** Кольцевой буфер строк для экрана логов. */
class LogStore {
    private val time = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val lines = ArrayDeque<String>()
    private val listeners = CopyOnWriteArrayList<(List<String>) -> Unit>()

    @Synchronized
    fun add(message: String) {
        lines.addLast("${time.format(Date())} $message")
        while (lines.size > MAX_LINES) lines.removeFirst()
        val snapshot = lines.toList()
        listeners.forEach { it(snapshot) }
    }

    @Synchronized
    fun snapshot(): List<String> = lines.toList()

    @Synchronized
    fun clear() {
        lines.clear()
        listeners.forEach { it(emptyList()) }
    }

    fun subscribe(listener: (List<String>) -> Unit) {
        listeners.add(listener)
        listener(snapshot())
    }

    fun unsubscribe(listener: (List<String>) -> Unit) = listeners.remove(listener)

    private companion object {
        const val MAX_LINES = 400
    }
}
