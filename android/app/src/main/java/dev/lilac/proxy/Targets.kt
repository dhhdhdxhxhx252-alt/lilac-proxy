package dev.lilac.proxy

/** Статичные сведения о дата-центрах Telegram, нужные для fallback без WS. */
object Targets {
    val DC_DEFAULT_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.50",
        2 to "149.154.167.51",
        3 to "149.154.175.100",
        4 to "149.154.167.91",
        5 to "149.154.171.5",
        203 to "91.105.192.100",
    )

    val DC_TITLES: Map<Int, String> = mapOf(
        1 to "DC1 · Амстердам",
        2 to "DC2 · Амстердам",
        3 to "DC3 · Лондон",
        4 to "DC4 · Майами",
        5 to "DC5 · Сингапур",
        203 to "DC203 · Амстердам (медиа → DC2)",
    )

    /** DC, у которого нет своего WS-шлюза: пул берёт домен другого. */
    private val DC_OVERRIDES: Map<Int, Int> = mapOf(203 to 2)

    fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
        val effective = DC_OVERRIDES[dc] ?: dc
        val primary = "kws$effective.web.telegram.org"
        val secondary = "kws$effective-1.web.telegram.org"
        return if (isMedia) listOf(secondary, primary) else listOf(primary, secondary)
    }

    fun fallbackIp(dc: Int): String? = DC_DEFAULT_IPS[dc]

    /** Пользовательский адрес DC: для медиа ключ хранится как -dc. */
    fun configuredTarget(overrides: Map<Int, String>, dc: Int, isMedia: Boolean): String? {
        if (isMedia) overrides[-dc]?.takeIf { it.isNotBlank() }?.let { return it }
        return overrides[dc]?.takeIf { it.isNotBlank() }
    }

    fun telegramLink(host: String, port: Int, secretHex: String): String =
        "tg://proxy?server=$host&port=$port&secret=${secretHex.lowercase()}"
}
