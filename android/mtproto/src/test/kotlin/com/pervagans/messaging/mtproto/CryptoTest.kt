package com.pervagans.messaging.mtproto

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Cross-implementation tests.
 *
 * The vectors below are asserted identically in `pkg/mtproto/mtproto_test.go`
 * and `web/lib/mtproto/crypto.test.mjs`. Three independent implementations of
 * the same specification will drift apart eventually; pinning the same values
 * in all three is what turns that drift into a build failure rather than an
 * Android client that silently cannot decrypt anything.
 */
class CryptoTest {

    @Test
    fun `AES-IGE matches the published known-answer vector`() {
        // The AES-128-IGE case from the original OpenSSL IGE patch.
        val key = Crypto.fromHex("000102030405060708090A0B0C0D0E0F")
        val iv = Crypto.fromHex(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        )
        val plain = Crypto.fromHex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        val want = "1a8519a6557be652e9da8e43da4ef4453cf456b4ca488aa383c79c98b34797cb"

        val got = Crypto.igeEncrypt(key, iv, plain)
        assertEquals(want, Crypto.toHex(got), "IGE encryption diverged from the reference vector")

        val back = Crypto.igeDecrypt(key, iv, got)
        assertContentEquals(plain, back, "IGE decryption did not invert encryption")
    }

    @Test
    fun `the key derivation matches the Go server byte for byte`() {
        // Identical inputs to TestKeyDerivationCrossImplementation in Go and
        // to the matching case in the web test suite.
        val authKey = ByteArray(256) { ((it * 13) and 0xff).toByte() }
        val body = "the quick brown fox".toByteArray(Charsets.UTF_8)

        val msgKey = Crypto.msgKey(authKey, body, Crypto.CLIENT_TO_SERVER)
        assertEquals(
            "93065c239f68031c3bb889e26ef945cd",
            Crypto.toHex(msgKey),
            "msg_key diverged from the Go implementation",
        )

        val (key, iv) = Crypto.deriveKeyIV(authKey, msgKey, Crypto.CLIENT_TO_SERVER)
        assertEquals(
            "1d3eed336606b3bb23b7e2eb98f0052222dd6b62bd5f9910f50139fa7128bd30",
            Crypto.toHex(key),
            "aes_key diverged from the Go implementation",
        )
        assertEquals(
            "924933f8f370ea91b725878863320ef5db29e5ef4291089972c4d94fe54688ff",
            Crypto.toHex(iv),
            "aes_iv diverged from the Go implementation",
        )
    }

    @Test
    fun `AES-256-IGE round trips at several sizes`() {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(32) { (255 - it).toByte() }

        for (size in listOf(16, 32, 256, 4096)) {
            val data = ByteArray(size) { ((it * 7) and 0xff).toByte() }
            val ct = Crypto.igeEncrypt(key, iv, data)
            assertEquals(size, ct.size)
            assertNotEquals(Crypto.toHex(data), Crypto.toHex(ct), "ciphertext equals plaintext")

            val pt = Crypto.igeDecrypt(key, iv, ct)
            assertContentEquals(data, pt, "round trip failed at $size bytes")
        }
    }

    @Test
    fun `AES-IGE rejects malformed input`() {
        val key = ByteArray(32)
        assertFailsWith<IllegalArgumentException> {
            Crypto.igeEncrypt(key, ByteArray(16), ByteArray(32))
        }
        assertFailsWith<IllegalArgumentException> {
            Crypto.igeEncrypt(key, ByteArray(32), ByteArray(17))
        }
        assertFailsWith<IllegalArgumentException> {
            Crypto.igeEncrypt(key, ByteArray(32), ByteArray(0))
        }
    }

    @Test
    fun `each direction gets its own key schedule`() {
        val authKey = ByteArray(256) { ((it * 13) and 0xff).toByte() }
        val body = "payload".toByteArray()

        val c2s = Crypto.msgKey(authKey, body, Crypto.CLIENT_TO_SERVER)
        val s2c = Crypto.msgKey(authKey, body, Crypto.SERVER_TO_CLIENT)
        assertNotEquals(Crypto.toHex(c2s), Crypto.toHex(s2c), "the x offset is not being applied")

        val a = Crypto.deriveKeyIV(authKey, c2s, Crypto.CLIENT_TO_SERVER)
        val b = Crypto.deriveKeyIV(authKey, c2s, Crypto.SERVER_TO_CLIENT)
        assertNotEquals(Crypto.toHex(a.key), Crypto.toHex(b.key))
        assertEquals(32, a.key.size)
        assertEquals(32, a.iv.size)
    }

    @Test
    fun `the constant-time comparison is correct`() {
        val a = byteArrayOf(1, 2, 3, 4)
        assertTrue(Crypto.constantTimeEquals(a, byteArrayOf(1, 2, 3, 4)))
        assertTrue(!Crypto.constantTimeEquals(a, byteArrayOf(1, 2, 3, 5)))
        assertTrue(!Crypto.constantTimeEquals(a, byteArrayOf(9, 2, 3, 4)))
        assertTrue(!Crypto.constantTimeEquals(a, byteArrayOf(1, 2, 3)))
    }

    /**
     * BigInteger.toByteArray prepends a sign byte when the top bit is set and
     * drops leading zeros otherwise, so a 256-byte value can come back at 255,
     * 256 or 257 bytes. Normalising is what stops the three implementations
     * deriving different-length keys from the same shared secret.
     */
    @Test
    fun `fixed-width conversion normalises every BigInteger shape`() {
        // Top bit set: toByteArray returns 257 bytes with a leading zero.
        val big = BigInteger.ONE.shiftLeft(2047)
        assertEquals(256, Crypto.toFixedBytes(big, 256).size)

        // Small: toByteArray returns 1 byte, and it must be right-aligned.
        val small = BigInteger.valueOf(255)
        val padded = Crypto.toFixedBytes(small, 256)
        assertEquals(256, padded.size)
        assertEquals(255, padded[255].toInt() and 0xff)
        assertEquals(0, padded[0].toInt())

        // Round trip.
        assertEquals(small, Crypto.fromBytes(padded))
        assertEquals(big, Crypto.fromBytes(Crypto.toFixedBytes(big, 256)))
    }
}
