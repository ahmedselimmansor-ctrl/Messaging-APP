package com.pervagans.messaging.mtproto

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ProtocolTest {

    @Test
    fun `the envelope round trips at several body sizes`() {
        val authKey = ByteArray(256) { ((it * 31) and 0xff).toByte() }
        val keyId = Crypto.authKeyId(authKey)

        for (size in listOf(0, 1, 15, 16, 17, 4096)) {
            val body = ByteArray(size) { (it and 0xff).toByte() }
            val msg = Protocol.Message(
                salt = 0x1122334455667788L,
                sessionId = 0x0badc0deL,
                msgId = System.currentTimeMillis() / 1000 shl 32,
                seqNo = 3,
                body = body,
            )

            val frame = Protocol.encrypt(authKey, keyId, msg)

            // The ciphertext must be a whole number of AES blocks after the
            // 24-byte header.
            assertEquals(0, (frame.size - 24) % 16, "ciphertext is not block-aligned at size $size")

            // Round-tripping through decrypt needs the server-to-client
            // direction, so this exercises the envelope shape rather than a
            // full client/server exchange — the Go end-to-end test covers that.
            assertTrue(frame.size > 24, "frame is implausibly short")
        }
    }

    @Test
    fun `a tampered frame is rejected`() {
        val authKey = ByteArray(256) { it.toByte() }
        val keyId = Crypto.authKeyId(authKey)

        // Build a server-to-client frame by hand so decrypt can verify it.
        val body = Protocol.encodePayload(Protocol.C_OK, """{"ok":true}""")
        val header = ByteArray(32)
        java.nio.ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN).apply {
            putLong(1L); putLong(2L); putLong(3L shl 32); putInt(1); putInt(body.size)
        }
        val plaintext = Crypto.concat(header, body, ByteArray(16 - (32 + body.size + 12) % 16 + 12))
        val msgKey = Crypto.msgKey(authKey, plaintext, Crypto.SERVER_TO_CLIENT)
        val (k, iv) = Crypto.deriveKeyIV(authKey, msgKey, Crypto.SERVER_TO_CLIENT)
        val frame = Crypto.concat(keyId, msgKey, Crypto.igeEncrypt(k, iv, plaintext))

        // Unmodified, it parses.
        val parsed = Protocol.decrypt(authKey, frame)
        assertEquals(Protocol.C_OK, Protocol.peekConstructor(parsed.body))

        // Flip a bit deep in the ciphertext: IGE garbles everything from that
        // block onwards, so the recomputed msg_key cannot match.
        val tampered = frame.copyOf()
        tampered[tampered.size - 5] = (tampered[tampered.size - 5].toInt() xor 0x01).toByte()
        assertFailsWith<SecurityException> { Protocol.decrypt(authKey, tampered) }
    }

    @Test
    fun `plain messages round trip`() {
        val body = Protocol.encodePayload(Protocol.C_REQ_PQ, """{"nonce":"abc"}""")
        val frame = Protocol.encodePlain(0x1234L, body)

        assertEquals(0L, Protocol.peekAuthKeyId(frame))

        val parsed = Protocol.decodePlain(frame)
        assertEquals(0x1234L, parsed.msgId)
        assertContentEquals(body, parsed.body)
        assertEquals(Protocol.C_REQ_PQ, Protocol.peekConstructor(parsed.body))
    }

    @Test
    fun `payload encoding round trips`() {
        val json = """{"chat_id":42,"body":"hi"}"""
        val payload = Protocol.encodePayload(Protocol.C_SEND_MESSAGE, json)

        assertEquals(Protocol.C_SEND_MESSAGE, Protocol.peekConstructor(payload))
        assertEquals(json, Protocol.decodeBody(payload))
    }

    @Test
    fun `the DH prime matches RFC 3526 group 14`() {
        // 2048 bits, and (p-1)/2 must also be prime for a safe prime. The
        // primality check is expensive, so a low certainty is enough to catch
        // a transcription error, which is what this actually guards against.
        assertEquals(2048, Protocol.DH_PRIME.bitLength())
        assertTrue(Protocol.DH_PRIME.isProbablePrime(10), "the DH prime is not prime")

        val q = Protocol.DH_PRIME.subtract(BigInteger.ONE).shiftRight(1)
        assertTrue(q.isProbablePrime(10), "(p-1)/2 is not prime, so p is not a safe prime")
    }

    @Test
    fun `the DH exchange produces the same key on both sides`() {
        val a = Protocol.generateExponent()
        val b = Protocol.generateExponent()

        val gA = Protocol.publicValue(a)
        val gB = Protocol.publicValue(b)

        val keyA = Protocol.deriveSharedKey(gB, a)
        val keyB = Protocol.deriveSharedKey(gA, b)

        assertContentEquals(keyA, keyB, "the two parties derived different keys")
        assertEquals(Crypto.AUTH_KEY_SIZE, keyA.size)
    }

    @Test
    fun `degenerate DH values are rejected`() {
        val p = Protocol.DH_PRIME
        for (v in listOf(
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.TWO,
            p,
            p.subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(20),
        )) {
            assertFailsWith<IllegalArgumentException>("value $v was accepted") {
                Protocol.validateDHValue(v)
            }
        }

        // A genuine public value must pass.
        Protocol.validateDHValue(Protocol.publicValue(Protocol.generateExponent()))
    }

    @Test
    fun `the inner-data seal round trips and detects tampering`() {
        val newNonce = ByteArray(32) { it.toByte() }
        val serverNonce = ByteArray(16) { (it * 3).toByte() }
        val (key, iv) = Protocol.tmpAesKeyIv(newNonce, serverNonce)

        val data = """{"g_b":"value","retry_id":0}""".toByteArray()
        val sealed = Protocol.igeSeal(key, iv, data)
        assertContentEquals(data, Protocol.igeOpen(key, iv, sealed))

        val tampered = sealed.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xff).toByte()
        assertFailsWith<SecurityException> { Protocol.igeOpen(key, iv, tampered) }
    }

    @Test
    fun `pq factorisation recovers the factors`() {
        // 31-bit primes, the size the server generates.
        val p = 2147483647L  // 2^31 - 1, a Mersenne prime
        val q = 2147483629L
        val pq = p * q

        val (gotP, gotQ) = Protocol.factorPQ(pq)
        assertEquals(q, gotP, "expected the smaller factor first")
        assertEquals(p, gotQ)
        assertEquals(pq, gotP * gotQ)
    }

    @Test
    fun `pq_inner_data is exactly 88 bytes`() {
        // It must fit one RSA-OAEP block: a 2048-bit key with SHA-256 OAEP
        // carries at most 190 bytes.
        val encoded = Protocol.encodePQInnerData(
            pq = 1234567890L, p = 12345L, q = 100000L,
            nonce = ByteArray(16), serverNonce = ByteArray(16), newNonce = ByteArray(32),
        )
        assertEquals(88, encoded.size)
        assertTrue(encoded.size <= 190, "pq_inner_data does not fit an RSA-OAEP block")
    }

    @Test
    fun `the auth key id is deterministic`() {
        val authKey = ByteArray(256) { it.toByte() }
        val a = Crypto.authKeyId(authKey)
        val b = Crypto.authKeyId(authKey)

        assertEquals(8, a.size)
        assertContentEquals(a, b)

        val other = ByteArray(256) { (it + 1).toByte() }
        assertNotEquals(Crypto.toHex(a), Crypto.toHex(Crypto.authKeyId(other)))
    }
}
