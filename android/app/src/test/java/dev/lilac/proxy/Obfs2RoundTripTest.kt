package dev.lilac.proxy

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * Сквозная проверка цепочки преобразований: фейковый Telegram-клиент и фейковый DC
 * используют те же потоки, что и настоящая сторона, поэтому байты обязаны дойти целыми.
 */
class Obfs2RoundTripTest {
    private val random = SecureRandom()

    /** Клиентская версия init: тот же приём с хвостом, что и в Handshake.relayInit. */
    private fun craftClientInit(secret: ByteArray, proto: Int, dc: Short): ByteArray {
        val init = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)
        val encrypted = init.copyOf()
        Obfs2.clientDecryptor(init, secret).xor(encrypted)

        val tail = ByteArray(8)
        writeLeInt(tail, 0, proto)
        writeLeShort(tail, 4, dc)
        val padding = ByteArray(2).also(random::nextBytes)
        tail[6] = padding[0]
        tail[7] = padding[1]
        for (i in 0 until 8) {
            val keystream = (encrypted[56 + i].toInt() xor init[56 + i].toInt()).toByte()
            init[56 + i] = (tail[i].toInt() xor keystream.toInt()).toByte()
        }
        return init
    }

    @Test
    fun `поток клиента симметричен — шифрование и расшифование дают те же байты`() {
        val secret = ByteArray(16).also(random::nextBytes)
        val raw = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)

        val plain = raw.copyOf()
        Obfs2.clientDecryptor(raw, secret).xor(plain)
        val back = plain.copyOf()
        Obfs2.clientDecryptor(raw, secret).xor(back)
        assertArrayEquals(raw, back)
    }

    @Test
    fun `proxy читает из init клиента протокол и DC`() {
        val secret = ByteArray(16).also(random::nextBytes)
        val raw = craftClientInit(secret, PROTO_INTERMEDIATE, -4)

        val decryptor = Obfs2.clientDecryptor(raw, secret)
        val plain = raw.copyOf()
        decryptor.xor(plain)

        val info = Handshake.clientInit(plain)
        assertTrue("init не разобрался", info != null)
        assertEquals(PROTO_INTERMEDIATE, info!!.proto)
        assertEquals(4, info.dc)
        assertTrue(info.isMedia)
    }

    @Test
    fun `неверный секрет не даёт валидного протокола`() {
        val secret = ByteArray(16).also(random::nextBytes)
        val raw = craftClientInit(secret, PROTO_INTERMEDIATE, 1)
        val intruder = ByteArray(16).also(random::nextBytes)

        val plain = raw.copyOf()
        Obfs2.clientDecryptor(raw, intruder).xor(plain)
        assertEquals(null, Handshake.clientInit(plain))
    }

    @Test
    fun `восходящий поток клиента доходит до DC в открытом виде`() {
        val secret = ByteArray(16).also(random::nextBytes)
        val raw = craftClientInit(secret, PROTO_INTERMEDIATE, 2)
        val relayInit = Handshake.relayInit(PROTO_INTERMEDIATE, 2, isMedia = false)

        val clientStream = Obfs2.clientDecryptor(raw, secret)
        val proxyClientStream = Obfs2.clientDecryptor(raw, secret)
        val proxyRelayStream = Obfs2.relayEncryptor(relayInit)
        val dcRelayStream = Obfs2.relayEncryptor(relayInit)

        // все четыре потока сначала тратят 64 байта init, и только потом тело сообщений
        clientStream.xor(raw.copyOf())
        proxyClientStream.xor(ByteArray(Obfs2.HANDSHAKE_SIZE))
        proxyRelayStream.xor(ByteArray(Obfs2.HANDSHAKE_SIZE))
        dcRelayStream.xor(ByteArray(Obfs2.HANDSHAKE_SIZE))

        val message = ByteArray(204) { (it % 251).toByte() }
        val wire = message.copyOf()
        clientStream.xor(wire)

        proxyClientStream.xor(wire)
        assertArrayEquals(message, wire)
        val relayed = wire.copyOf()
        proxyRelayStream.xor(relayed)

        val atDc = relayed.copyOf()
        dcRelayStream.xor(atDc)
        assertArrayEquals(message, atDc)
    }

    @Test
    fun `ответ DC доходит до клиента через обратную пару потоков`() {
        val secret = ByteArray(16).also(random::nextBytes)
        val raw = craftClientInit(secret, PROTO_ABRIDGED, 5)
        val relayInit = Handshake.relayInit(PROTO_ABRIDGED, 5, isMedia = true)

        val reply = ByteArray(132) { (it % 97).toByte() }
        val wire = reply.copyOf()
        Obfs2.relayDecryptor(relayInit).xor(wire)

        val proxyRead = Obfs2.relayDecryptor(relayInit)
        val proxyWrite = Obfs2.clientEncryptor(raw, secret)
        proxyRead.xor(wire)
        assertArrayEquals(reply, wire)
        val toClient = wire.copyOf()
        proxyWrite.xor(toClient)

        Obfs2.clientEncryptor(raw, secret).xor(toClient)
        assertArrayEquals(reply, toClient)
    }

    @Test
    fun `relay init перекладывает хвост, не меняя ключи`() {
        val proto = PROTO_PADDED_INTERMEDIATE
        val relayInit = Handshake.relayInit(proto, 203, isMedia = true)

        assertNotEquals(0xEF.toByte(), relayInit[0])
        assertTrue(relayInit.copyOfRange(4, 8).any { it != 0.toByte() })

        val dcView = relayInit.copyOf()
        Obfs2.relayEncryptor(relayInit).xor(dcView)
        assertEquals(proto, readLeInt(dcView, 56))
        assertEquals(-203, readLeShort(dcView, 60).toInt())
    }

    @Test
    fun `копия потока продолжается с того же места`() {
        val secret = ByteArray(16).also(random::nextBytes)
        val raw = ByteArray(Obfs2.HANDSHAKE_SIZE).also(random::nextBytes)
        val original = Obfs2.clientDecryptor(raw, secret).apply { xor(ByteArray(100)) }
        val clone = original.copy()
        val reference = Obfs2.clientDecryptor(raw, secret).apply { xor(ByteArray(100)) }

        val a = ByteArray(64) { (it % 13).toByte() }
        val b = a.copyOf()
        clone.xor(a)
        reference.xor(b)
        assertArrayEquals(a, b)
        assertEquals(164L, clone.bytesProcessed)
    }
}
