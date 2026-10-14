package dev.lilac.proxy

import java.security.SecureRandom

const val PROTO_ABRIDGED = -0x10101011          // 0xEFEFEFEF
const val PROTO_INTERMEDIATE = 0xEEEEEEEE.toInt()
const val PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD.toInt()

fun validProto(proto: Int) =
    proto == PROTO_ABRIDGED || proto == PROTO_INTERMEDIATE || proto == PROTO_PADDED_INTERMEDIATE

fun protoTagToType(proto: Int): Int = when (proto) {
    PROTO_INTERMEDIATE -> PROTO_TYPE_INTERMEDIATE
    PROTO_PADDED_INTERMEDIATE -> PROTO_TYPE_PADDED_INTERMEDIATE
    else -> PROTO_TYPE_ABRIDGED
}

const val PROTO_TYPE_ABRIDGED = 0
const val PROTO_TYPE_INTERMEDIATE = 1
const val PROTO_TYPE_PADDED_INTERMEDIATE = 2

/** Что прокси вычитал из 64-байтного init клиента. */
data class ClientInit(val proto: Int, val dc: Int, val isMedia: Boolean) {
    val tag: String get() = if (isMedia) " DC$dc-M" else " DC$dc"
}

object Handshake {
    private val random = SecureRandom()

    /**
     * Разбирает уже расшифрованный init. Поток, которым он расшифрован, остаётся
     * у вызывающей стороны: им же читаются все остальные байты клиента.
     */
    fun clientInit(plain: ByteArray): ClientInit? {
        if (plain.size < Obfs2.HANDSHAKE_SIZE) return null
        val proto = readLeInt(plain, 56)
        if (!validProto(proto)) return null
        val rawDc = readLeShort(plain, 60)
        return ClientInit(proto = proto, dc = kotlin.math.abs(rawDc.toInt()), isMedia = rawDc < 0)
    }

    fun isHttpTransport(data: ByteArray): Boolean {
        if (data.size < 4) return false
        return startsWith(data, 0, 'P', 'O', 'S', 'T') ||
            startsWith(data, 0, 'G', 'E', 'T') ||
            startsWith(data, 0, 'H', 'E', 'A', 'D') ||
            startsWith(data, 0, 'O', 'P', 'T', 'I', 'O', 'N', 'S')
    }

    private fun startsWith(data: ByteArray, offset: Int, vararg chars: Char): Boolean {
        if (data.size < offset + chars.size) return false
        for ((i, c) in chars.withIndex()) {
            if (data[offset + i].toInt() != c.code) return false
        }
        return true
    }

    /**
     * 64-байтный init, который прокси отправляет на сторону DC вместо клиента.
     * Хвост подгоняется так, чтобы после шифрования там оказался нужный proto tag и DC.
     */
    fun relayInit(proto: Int, dc: Int, isMedia: Boolean): ByteArray {
        val init = ByteArray(Obfs2.HANDSHAKE_SIZE)
        while (true) {
            random.nextBytes(init)
            if (!usableRelayInit(init)) continue
            break
        }

        val dcIndex = (if (isMedia) -dc else dc).toShort()
        val tail = ByteArray(8)
        writeLeInt(tail, 0, proto)
        writeLeShort(tail, 4, dcIndex)
        val padding = ByteArray(2).also(random::nextBytes)
        tail[6] = padding[0]
        tail[7] = padding[1]

        val encrypted = init.copyOf()
        Obfs2.relayEncryptor(init).xor(encrypted)
        for (i in 0 until 8) {
            val keystream = (encrypted[56 + i].toInt() xor init[56 + i].toInt()).toByte()
            init[56 + i] = (tail[i].toInt() xor keystream.toInt()).toByte()
        }
        return init
    }

    /** init не должен напоминать HTTP, TLS hello или известный тег протокола. */
    private fun usableRelayInit(init: ByteArray): Boolean {
        if (init[0] == 0xEF.toByte()) return false
        val head = init.copyOfRange(0, 4)
        if (head contentEquals "HEAD".toByteArray()) return false
        if (head contentEquals "POST".toByteArray()) return false
        if (head contentEquals "GET ".toByteArray()) return false
        if (head contentEquals byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())) return false
        if (head contentEquals byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte())) return false
        val tlsHello = byteArrayOf(0x16, 0x03, 0x01, 0x02)
        if (head contentEquals tlsHello) return false
        return init.copyOfRange(4, 8).any { it != 0.toByte() }
    }
}

internal fun readLeInt(source: ByteArray, offset: Int): Int =
    (source[offset].toInt() and 0xFF) or
        ((source[offset + 1].toInt() and 0xFF) shl 8) or
        ((source[offset + 2].toInt() and 0xFF) shl 16) or
        ((source[offset + 3].toInt() and 0xFF) shl 24)

internal fun readLeShort(source: ByteArray, offset: Int): Short =
    ((source[offset].toInt() and 0xFF) or ((source[offset + 1].toInt() and 0xFF) shl 8)).toShort()

internal fun writeLeShort(target: ByteArray, offset: Int, value: Short) {
    target[offset] = (value.toInt() and 0xFF).toByte()
    target[offset + 1] = ((value.toInt() shr 8) and 0xFF).toByte()
}

internal fun writeLeInt(target: ByteArray, offset: Int, value: Int) {
    for (i in 0 until 4) target[offset + i] = ((value shr (8 * i)) and 0xFF).toByte()
}
