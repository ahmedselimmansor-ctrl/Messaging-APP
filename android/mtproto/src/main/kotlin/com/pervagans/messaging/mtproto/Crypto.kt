package com.pervagans.messaging.mtproto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * MTProto cryptography on the JVM.
 *
 * This is the third independent implementation of the same specification,
 * alongside `pkg/mtproto` in Go and `web/lib/mtproto` in TypeScript. All three
 * must agree byte for byte, which is why the same pinned vectors are asserted
 * in each one's test suite — a divergence here would break every Android
 * client and would not fail any server test.
 *
 * The JVM has one advantage over the browser: `AES/ECB/NoPadding` is exposed
 * directly, so the raw block primitive IGE is built from needs no reconstruction
 * from CBC.
 */
object Crypto {

    private val secureRandom = SecureRandom()

    const val AUTH_KEY_SIZE = 256

    /** Direction selects which half of the key schedule to use. */
    const val CLIENT_TO_SERVER = 0
    const val SERVER_TO_CLIENT = 8

    // -----------------------------------------------------------------------
    // Byte helpers
    // -----------------------------------------------------------------------

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also(secureRandom::nextBytes)

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var offset = 0
        for (p in parts) {
            p.copyInto(out, offset)
            offset += p.size
        }
        return out
    }

    /**
     * Compares two arrays without leaking their contents through timing.
     *
     * Used for msg_key and nonce-hash verification. A short-circuiting compare
     * would let an attacker forge a value one byte at a time.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun toHex(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it) }

    fun fromHex(s: String): ByteArray {
        val clean = s.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
        return ByteArray(clean.length / 2) {
            clean.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }

    // -----------------------------------------------------------------------
    // AES-IGE
    // -----------------------------------------------------------------------

    private fun aesCipher(key: ByteArray, mode: Int): Cipher =
        Cipher.getInstance("AES/ECB/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"))
        }

    private fun xor(dst: ByteArray, a: ByteArray, aOff: Int, b: ByteArray, bOff: Int) {
        for (i in 0 until 16) dst[i] = (a[aOff + i].toInt() xor b[bOff + i].toInt()).toByte()
    }

    /**
     * AES-256-IGE encryption.
     *
     *     y[i] = E(x[i] ⊕ y[i-1]) ⊕ x[i-1]
     *
     * with y[-1] and x[-1] taken from the first and second halves of the
     * 32-byte IV.
     */
    fun igeEncrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        require(iv.size == 32) { "mtproto: the IGE IV must be 32 bytes, got ${iv.size}" }
        require(data.isNotEmpty() && data.size % 16 == 0) {
            "mtproto: IGE data must be a non-empty multiple of 16 bytes, got ${data.size}"
        }

        val cipher = aesCipher(key, Cipher.ENCRYPT_MODE)
        val out = ByteArray(data.size)

        val prevCipher = iv.copyOfRange(0, 16)
        val prevPlain = iv.copyOfRange(16, 32)
        val buf = ByteArray(16)

        var i = 0
        while (i < data.size) {
            xor(buf, data, i, prevCipher, 0)
            val encrypted = cipher.doFinal(buf)
            for (j in 0 until 16) {
                out[i + j] = (encrypted[j].toInt() xor prevPlain[j].toInt()).toByte()
            }
            out.copyInto(prevCipher, 0, i, i + 16)
            data.copyInto(prevPlain, 0, i, i + 16)
            i += 16
        }
        return out
    }

    /**
     * AES-256-IGE decryption.
     *
     *     x[i] = D(y[i] ⊕ x[i-1]) ⊕ y[i-1]
     */
    fun igeDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        require(iv.size == 32) { "mtproto: the IGE IV must be 32 bytes, got ${iv.size}" }
        require(data.isNotEmpty() && data.size % 16 == 0) {
            "mtproto: IGE data must be a non-empty multiple of 16 bytes, got ${data.size}"
        }

        val cipher = aesCipher(key, Cipher.DECRYPT_MODE)
        val out = ByteArray(data.size)

        val prevCipher = iv.copyOfRange(0, 16)
        val prevPlain = iv.copyOfRange(16, 32)
        val buf = ByteArray(16)

        var i = 0
        while (i < data.size) {
            xor(buf, data, i, prevPlain, 0)
            val decrypted = cipher.doFinal(buf)
            for (j in 0 until 16) {
                out[i + j] = (decrypted[j].toInt() xor prevCipher[j].toInt()).toByte()
            }
            data.copyInto(prevCipher, 0, i, i + 16)
            out.copyInto(prevPlain, 0, i, i + 16)
            i += 16
        }
        return out
    }

    // -----------------------------------------------------------------------
    // Digests
    // -----------------------------------------------------------------------

    fun sha256(vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(concat(*parts))

    /**
     * SHA-1 appears only as an identifier — auth key ids, RSA fingerprints —
     * and inside MTProto's specified handshake KDF. Never as a security
     * primitive on its own.
     */
    fun sha1(vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(concat(*parts))

    // -----------------------------------------------------------------------
    // MTProto 2.0 key derivation
    // -----------------------------------------------------------------------

    /**
     * msg_key = substr(SHA256(substr(auth_key, 88 + x, 32) ‖ plaintext), 8, 16)
     *
     * The digest covers a secret slice of the auth key, so only a key holder
     * can produce a valid msg_key. That is what authenticates the message.
     */
    fun msgKey(authKey: ByteArray, plaintext: ByteArray, x: Int): ByteArray {
        val digest = sha256(authKey.copyOfRange(88 + x, 88 + x + 32), plaintext)
        return digest.copyOfRange(8, 24)
    }

    /** The per-message AES key and IV. */
    data class KeyIV(val key: ByteArray, val iv: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is KeyIV && key.contentEquals(other.key) && iv.contentEquals(other.iv)

        override fun hashCode(): Int = key.contentHashCode() * 31 + iv.contentHashCode()
    }

    /**
     * Derives the per-message key schedule.
     *
     *     sha256_a = SHA256(msg_key ‖ substr(auth_key, x, 36))
     *     sha256_b = SHA256(substr(auth_key, 40 + x, 36) ‖ msg_key)
     *     aes_key  = a[0..8] ‖ b[8..24] ‖ a[24..32]
     *     aes_iv   = b[0..8] ‖ a[8..24] ‖ b[24..32]
     *
     * The interleave is deliberate: neither digest alone determines the key,
     * so leaking one does not hand over the schedule.
     */
    fun deriveKeyIV(authKey: ByteArray, msgKey: ByteArray, x: Int): KeyIV {
        require(msgKey.size == 16) { "mtproto: msg_key must be 16 bytes, got ${msgKey.size}" }

        val a = sha256(msgKey, authKey.copyOfRange(x, x + 36))
        val b = sha256(authKey.copyOfRange(40 + x, 40 + x + 36), msgKey)

        return KeyIV(
            key = concat(a.copyOfRange(0, 8), b.copyOfRange(8, 24), a.copyOfRange(24, 32)),
            iv = concat(b.copyOfRange(0, 8), a.copyOfRange(8, 24), b.copyOfRange(24, 32)),
        )
    }

    /** The 64-bit auth key identifier: substr(SHA1(auth_key), 12, 8). */
    fun authKeyId(authKey: ByteArray): ByteArray =
        sha1(authKey).copyOfRange(12, 20)

    // -----------------------------------------------------------------------
    // Big integers
    // -----------------------------------------------------------------------

    /**
     * Converts a BigInteger to a fixed-width big-endian array.
     *
     * BigInteger.toByteArray() prepends a zero byte when the top bit is set,
     * and drops leading zeros otherwise — so a shared secret comes back at
     * 255, 256 or 257 bytes depending on its value. Normalising here is what
     * stops the three implementations deriving different-length keys from the
     * same secret, which would fail in roughly one exchange in 256.
     */
    fun toFixedBytes(v: BigInteger, size: Int): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(size)
        when {
            raw.size == size -> raw.copyInto(out)
            raw.size > size -> raw.copyInto(out, 0, raw.size - size, raw.size)
            else -> raw.copyInto(out, size - raw.size)
        }
        return out
    }

    fun fromBytes(b: ByteArray): BigInteger = BigInteger(1, b)
}
