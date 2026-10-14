package dev.lilac.proxy

/**
 * Нарезает восходящий поток на цельные MTProto-сообщения, чтобы каждое ушло
 * отдельным WebSocket-фреймом. Длины читает из расшифрованных байт, а режет
 * зашифрованные — поэтому держит два зеркала буфера.
 */
class MsgSplitter(relayInit: ByteArray, proto: Int) {
    private val stream = AesCtrStream(relayInit.part(8, 40), relayInit.part(40, 56))
    private val protoType = protoTagToType(proto)
    private val cipherBuf = ByteQueue()
    private val plainBuf = ByteQueue()
    private var disabled = false

    init {
        // первые 64 байта (сам init) уже ушли в поток, сдвигаем keystream
        stream.xor(ByteArray(Obfs2.HANDSHAKE_SIZE))
    }

    fun split(chunk: ByteArray, offset: Int = 0, length: Int = chunk.size - offset): List<ByteArray> {
        if (length == 0) return emptyList()
        if (disabled) return listOf(chunk.copyOfRange(offset, offset + length))

        cipherBuf.append(chunk, offset, length)
        val decrypted = chunk.copyOfRange(offset, offset + length)
        stream.xor(decrypted)
        plainBuf.append(decrypted, 0, decrypted.size)

        val parts = ArrayList<ByteArray>()
        while (cipherBuf.size > 0) {
            val packetLen = nextPacketLen()
            if (packetLen < 0) break
            if (packetLen == 0) {
                parts.add(cipherBuf.takeAll())
                plainBuf.clear()
                disabled = true
                break
            }
            if (cipherBuf.size < packetLen) break
            parts.add(cipherBuf.take(packetLen))
            plainBuf.skip(packetLen)
        }
        if (cipherBuf.size == 0) {
            cipherBuf.clear()
            plainBuf.clear()
        }
        return parts
    }

    /** Хвост при закрытии соединения: недобранное сообщение отправляем как есть. */
    fun flush(): List<ByteArray> = if (cipherBuf.size == 0) emptyList() else listOf(cipherBuf.takeAll())

    /** -1 — данных пока мало, 0 — поток больше не похож на MTProto, дальше не режем. */
    private fun nextPacketLen(): Int {
        if (plainBuf.size == 0) return -1
        return when (protoType) {
            PROTO_TYPE_ABRIDGED -> {
                val first = plainBuf.byteAt(0).toInt() and 0x7F
                val headerLen: Int
                val payloadLen: Int
                if (first == 0x7F) {
                    if (plainBuf.size < 4) return -1
                    payloadLen = ((plainBuf.byteAt(1).toInt() and 0xFF) or
                        ((plainBuf.byteAt(2).toInt() and 0xFF) shl 8) or
                        ((plainBuf.byteAt(3).toInt() and 0xFF) shl 16)) * 4
                    headerLen = 4
                } else {
                    payloadLen = first * 4
                    headerLen = 1
                }
                if (payloadLen <= 0) return 0
                val packetLen = headerLen + payloadLen
                if (plainBuf.size < packetLen) -1 else packetLen
            }

            PROTO_TYPE_INTERMEDIATE, PROTO_TYPE_PADDED_INTERMEDIATE -> {
                if (plainBuf.size < 4) return -1
                val payloadLen = readLeInt(plainBuf.bytesAt(0, 4), 0) and 0x7FFFFFFF
                if (payloadLen <= 0) return 0
                val packetLen = 4 + payloadLen
                if (plainBuf.size < packetLen) -1 else packetLen
            }

            else -> 0
        }
    }
}

/** Байтовое окно с читающим курсором: дешёвые append/skip на горячем пути. */
class ByteQueue(initial: Int = 4096) {
    private var data = ByteArray(initial)
    private var head = 0
    private var tail = 0

    val size: Int get() = tail - head

    fun append(source: ByteArray, offset: Int, length: Int) {
        if (length == 0) return
        ensureCapacity(size + length)
        System.arraycopy(source, offset, data, tail, length)
        tail += length
    }

    fun byteAt(index: Int): Byte = data[head + index]

    fun bytesAt(index: Int, length: Int): ByteArray {
        val out = ByteArray(length)
        System.arraycopy(data, head + index, out, 0, length)
        return out
    }

    fun skip(count: Int) {
        head += count
        if (head == tail) clear() else compactIfNeeded()
    }

    fun take(count: Int): ByteArray {
        val out = bytesAt(0, count)
        skip(count)
        return out
    }

    fun takeAll(): ByteArray = take(size)

    fun clear() {
        head = 0
        tail = 0
    }

    private fun ensureCapacity(minimum: Int) {
        if (minimum <= data.size - head) return
        val grown = ByteArray(maxOf(minimum + head, data.size * 2))
        System.arraycopy(data, head, grown, 0, size)
        tail = size
        head = 0
        data = grown
    }

    private fun compactIfNeeded() {
        if (head < data.size / 2) return
        System.arraycopy(data, head, data, 0, size)
        tail = size
        head = 0
    }
}
