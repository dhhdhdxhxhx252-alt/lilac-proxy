package dev.lilac.proxy

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/** Нарезка восходящего потока на цельные MTProto-сообщения. */
class MsgSplitterTest {
    private val random = SecureRandom()

    /** Поток DC: те же ключи, что у MsgSplitter, плюс пропуск 64 байт init. */
    private fun relayStream(relayInit: ByteArray) =
        AesCtrStream(relayInit.part(8, 40), relayInit.part(40, 56)).apply {
            xor(ByteArray(Obfs2.HANDSHAKE_SIZE))
        }

    private fun intermediate(payloadSize: Int): ByteArray {
        val body = ByteArray(payloadSize).also(random::nextBytes)
        val packet = ByteArray(4 + payloadSize)
        writeLeInt(packet, 0, payloadSize)
        System.arraycopy(body, 0, packet, 4, payloadSize)
        return packet
    }

    private fun abridged(payloadSize: Int): ByteArray {
        val body = ByteArray(payloadSize).also(random::nextBytes)
        val packet = ByteArray(1 + payloadSize)
        packet[0] = (payloadSize / 4).toByte()
        System.arraycopy(body, 0, packet, 1, payloadSize)
        return packet
    }

    @Test
    fun `intermediate режет по длине в первых четырёх байтах`() {
        val relayInit = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)
        val packets = listOf(intermediate(64), intermediate(4 + 300), intermediate(12))
        val plain = packets.fold(ByteArray(0)) { acc, part -> acc + part }
        val stream = relayStream(relayInit)
        val cipher = plain.copyOf()
        stream.xor(cipher)

        val splitter = MsgSplitter(relayInit, PROTO_INTERMEDIATE)
        val parts = splitter.split(cipher)

        assertEquals(packets.map { it.size }, parts.map { it.size })
        assertEquals(cipher.toList(), parts.fold(ByteArray(0)) { a, b -> a + b }.toList())
    }

    @Test
    fun `abridged читает однобайтный заголовок — длина делена на четыре`() {
        val relayInit = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)
        val packets = listOf(abridged(4 * 20), abridged(4 * 1))
        val plain = packets.fold(ByteArray(0)) { acc, part -> acc + part }
        val cipher = plain.copyOf()
        relayStream(relayInit).xor(cipher)

        val splitter = MsgSplitter(relayInit, PROTO_ABRIDGED)
        val parts = splitter.split(cipher)
        assertEquals(packets.map { it.size }, parts.map { it.size })
    }

    @Test
    fun `недошедший пакет остаётся в буфере и уходит во flush`() {
        val relayInit = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)
        val packet = intermediate(80)
        val cipher = packet.copyOf()
        relayStream(relayInit).xor(cipher)

        val splitter = MsgSplitter(relayInit, PROTO_INTERMEDIATE)
        assertEquals(emptyList<ByteArray>(), splitter.split(cipher.copyOfRange(0, 20)))
        assertEquals(emptyList<ByteArray>(), splitter.split(cipher.copyOfRange(20, 40)))
        val rest = splitter.split(cipher.copyOfRange(40, cipher.size))
        assertEquals(listOf(84), rest.map { it.size })
        assertEquals(emptyList<ByteArray>(), splitter.flush())
    }

    @Test
    fun `нулевая длина выключает нарезку и поток идёт как есть`() {
        val relayInit = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)
        val plain = ByteArray(4) + ByteArray(20).also(random::nextBytes)
        val cipher = plain.copyOf()
        relayStream(relayInit).xor(cipher)

        val splitter = MsgSplitter(relayInit, PROTO_INTERMEDIATE)
        val parts = splitter.split(cipher)
        assertEquals(1, parts.size)
        assertEquals(cipher.size, parts.first().size)

        val next = ByteArray(30).also(random::nextBytes)
        val passthrough = splitter.split(next)
        assertEquals(listOf(30), passthrough.map { it.size })
        assertTrue(splitter.flush().isEmpty())
    }
}
