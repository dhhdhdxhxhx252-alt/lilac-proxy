package dev.lilac.proxy

import android.content.Context
import org.json.JSONObject
import java.security.SecureRandom

/** Снимок настроек на момент запуска прокси. */
data class ProxyConfig(
    val secret: ByteArray,
    val port: Int,
    val dcOverrides: Map<Int, String>,
    val preferWs: Boolean,
    val tcpFallback: Boolean,
) {
    val secretHex: String get() = Obfs2.toHex(secret)

    companion object {
        fun randomSecretHex(): String {
            val bytes = ByteArray(16)
            SecureRandom().nextBytes(bytes)
            return Obfs2.toHex(bytes)
        }
    }
}

class Settings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    var secretHex: String
        get() = prefs.getString(KEY_SECRET, null) ?: ProxyConfig.randomSecretHex().also { secretHex = it }
        set(value) = prefs.edit().putString(KEY_SECRET, value).apply()

    var port: Int
        get() = prefs.getInt(KEY_PORT, DEFAULT_PORT)
        set(value) = prefs.edit().putInt(KEY_PORT, value).apply()

    var preferWs: Boolean
        get() = prefs.getBoolean(KEY_WS, true)
        set(value) = prefs.edit().putBoolean(KEY_WS, value).apply()

    var tcpFallback: Boolean
        get() = prefs.getBoolean(KEY_TCP_FALLBACK, true)
        set(value) = prefs.edit().putBoolean(KEY_TCP_FALLBACK, value).apply()

    /** Ключ карты: dc, для медиа-DC значение хранится под отрицательным ключом. */
    var dcOverrides: Map<Int, String>
        get() {
            val raw = prefs.getString(KEY_DC_TARGETS, null) ?: return emptyMap()
            return runCatching {
                val json = JSONObject(raw)
                json.keys().asSequence().associate { it.toInt() to json.getString(it) }
            }.getOrDefault(emptyMap())
        }
        set(value) {
            val json = JSONObject()
            value.forEach { (dc, target) -> if (target.isNotBlank()) json.put(dc.toString(), target) }
            prefs.edit().putString(KEY_DC_TARGETS, json.toString()).apply()
        }

    fun config(): ProxyConfig {
        val secret = runCatching { Obfs2.parseSecret(secretHex) }.getOrElse {
            ProxyConfig.randomSecretHex().also { secretHex = it }.let { Obfs2.parseSecret(it) }
        }
        return ProxyConfig(secret, port, dcOverrides, preferWs, tcpFallback)
    }

    private companion object {
        const val NAME = "lilac"
        const val KEY_SECRET = "secret"
        const val KEY_PORT = "port"
        const val KEY_WS = "prefer_ws"
        const val KEY_TCP_FALLBACK = "tcp_fallback"
        const val KEY_DC_TARGETS = "dc_targets"
        const val DEFAULT_PORT = 1443
    }
}
