package dev.lilac.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList

/** Глобальное состояние прокси, на которое подписан интерфейс. */
object ProxyState {
    val stats = ProxyStats()
    val log = LogStore()

    @Volatile
    var running: Boolean = false
        private set

    @Volatile
    var port: Int = -1
        private set

    private val listeners = CopyOnWriteArrayList<() -> Unit>()
    private val main = Handler(Looper.getMainLooper())

    fun started(port: Int) {
        running = true
        this.port = port
        emit()
    }

    fun stopped(message: String?) {
        running = false
        port = -1
        stats.connectionsActive.set(0)
        if (message != null) log.add(message)
        emit()
    }

    fun emit() {
        val snapshot = listeners.toList()
        if (Looper.myLooper() == Looper.getMainLooper()) {
            snapshot.forEach { it() }
        } else {
            main.post { snapshot.forEach { it() } }
        }
    }

    fun subscribe(listener: () -> Unit) {
        listeners.add(listener)
        listener()
    }

    fun unsubscribe(listener: () -> Unit) = listeners.remove(listener)
}

class ProxyService : Service() {
    private var server: ProxyServer? = null
    private val ticker = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            updateNotification()
            ticker.postDelayed(this, TICK_MS)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        if (server != null) return START_STICKY

        val config = Settings(this).config()
        val instance = ProxyServer(config, ProxyState.stats, ProxyState.log)
        val started = try {
            instance.start()
            true
        } catch (error: IOException) {
            ProxyState.log.add("Порт ${config.port} занят: ${error.message}")
            false
        } catch (error: SecurityException) {
            ProxyState.log.add("Система запретила слушать порт: ${error.message}")
            false
        }
        if (!started) {
            stopSelf(startId)
            return START_NOT_STICKY
        }

        server = instance
        promoteToForeground()
        ProxyState.started(instance.boundPort)
        ticker.post(tick)
        return START_STICKY
    }

    override fun onDestroy() {
        ticker.removeCallbacks(tick)
        shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): Nothing? = null

    private fun shutdown() {
        server?.stop()
        server = null
        ticker.removeCallbacks(tick)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        ProxyState.stopped(null)
    }

    private fun promoteToForeground() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), type)
    }

    private fun buildNotification(): Notification {
        ensureChannel()
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val open = PendingIntent.getActivity(
            this,
            2,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_lilac)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(summary())
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(true)
            .setContentIntent(open)
            .addAction(R.drawable.ic_stop, getString(R.string.notification_stop), stop)
            .build()
    }

    private fun updateNotification() {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification())
        ProxyState.emit()
    }

    private fun summary(): String {
        val up = ProxyState.stats.bytesUp.get()
        val down = ProxyState.stats.bytesDown.get()
        val active = ProxyState.stats.connectionsActive.get()
        return getString(R.string.notification_summary, humanBytes(up), humanBytes(down), active)
    }

    private fun ensureChannel() {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = getString(R.string.channel_description) }
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val ACTION_STOP = "dev.lilac.proxy.STOP"
        private const val CHANNEL_ID = "lilac-proxy"
        private const val NOTIFICATION_ID = 41
        private const val TICK_MS = 1_000L

        fun start(context: Context) {
            val intent = Intent(context, ProxyService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, ProxyService::class.java).setAction(ACTION_STOP))
        }
    }
}

internal fun humanBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes Б"
    val units = listOf("КБ", "МБ", "ГБ", "ТБ")
    var value = bytes.toDouble()
    var index = -1
    while (value >= 1024 && index < units.size - 1) {
        value /= 1024
        index++
    }
    return String.format("%.1f %s", value, units[index])
}
