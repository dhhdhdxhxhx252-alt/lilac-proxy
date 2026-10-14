package dev.lilac.proxy

import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-CTR поток ключей. XOR симметричен, поэтому режим всегда шифрование.
 * Смещённое состояние можно восстановить через [rewind], этим держится копия потока.
 */
class AesCtrStream(key: ByteArray, iv: ByteArray) {
    private val key = key.copyOf()
    private val iv = iv.copyOf()
    private var processed = 0L
    private var cipher = new(this.key, this.iv)

    val bytesProcessed: Long get() = processed

    fun xor(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
        val out = cipher.update(data, offset, length) ?: ByteArray(0)
        System.arraycopy(out, 0, data, offset, out.size)
        processed += length.toLong()
    }

    /** Новый поток с тем же состоянием: Rust-аналог делает это проматкой keystream. */
    fun copy(): AesCtrStream {
        val clone = AesCtrStream(key, iv)
        clone.advance(processed)
        return clone
    }

    private fun advance(bytes: Long) {
        val block = ByteArray(8192)
        var rest = bytes
        while (rest > 0) {
            val n = minOf(rest, block.size.toLong()).toInt()
            cipher.update(block, 0, n)
            processed += n.toLong()
            rest -= n.toLong()
        }
    }

    private companion object {
        fun new(key: ByteArray, iv: ByteArray): Cipher {
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            return cipher
        }
    }
}

/** Разбор MTProto-секрета прокси и вывод из него ключей obfs2. */
object Obfs2 {
    const val HANDSHAKE_SIZE = 64

    fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        for (part in parts) digest.update(part)
        return digest.digest()
    }

    /** Секрет — 32 hex-символа (16 байт), как в простой схеме obfs2. */
    fun parseSecret(hex: String): ByteArray {
        val clean = hex.trim().lowercase().replace(" ", "")
        require(clean.length == 32) { "Секрет должен быть 32 hex-символа" }
        require(clean.all { it in "0123456789abcdef" }) { "Секрет должен быть в hex" }
        return clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    /** Ключи потока, которым расшифровывается то, что прислал Telegram. */
    fun clientDecryptor(init: ByteArray, secret: ByteArray) =
        AesCtrStream(sha256(init.part(8, 40), secret), init.part(40, 56))

    /** Ключи потока, которым отвечает клиенту (ключи — из перевёрнутой части init). */
    fun clientEncryptor(init: ByteArray, secret: ByteArray): AesCtrStream {
        val reversed = reversedWindow(init)
        return AesCtrStream(sha256(reversed.part(0, 32), secret), reversed.part(32, 48))
    }

    /** Поток шифрования на сторону DC: секрета нет, ключи берутся из relay-init напрямую. */
    fun relayEncryptor(relayInit: ByteArray) =
        AesCtrStream(relayInit.part(8, 40), relayInit.part(40, 56))

    fun relayDecryptor(relayInit: ByteArray): AesCtrStream {
        val reversed = reversedWindow(relayInit)
        return AesCtrStream(reversed.part(0, 32), reversed.part(32, 48))
    }

    private fun reversedWindow(source: ByteArray): ByteArray {
        val window = source.part(8, 56)
        window.reverse()
        return window
    }
}

internal fun ByteArray.part(from: Int, until: Int) = Arrays.copyOfRange(this, from, until)

