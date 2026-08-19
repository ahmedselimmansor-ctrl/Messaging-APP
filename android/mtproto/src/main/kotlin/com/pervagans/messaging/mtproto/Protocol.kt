package com.pervagans.messaging.mtproto

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The MTProto message envelope, constructor ids and the Diffie-Hellman group.
 *
 * Mirrors `pkg/mtproto` in Go. The wire format is defined there; this is one
 * of the three implementations of it.
 */
object Protocol {

    // Handshake constructors, sent in plain messages.
    const val C_REQ_PQ = 0x60469778
    const val C_RES_PQ = 0x05162463
    const val C_REQ_DH_PARAMS = 0xd712e4be.toInt()
    const val C_SERVER_DH_PARAMS = 0xd0e8075c.toInt()
    const val C_SET_CLIENT_DH_PARAMS = 0xf5045f1f.toInt()
    const val C_DH_GEN_OK = 0x3bcbf734
    const val C_HANDSHAKE_ERROR = 0x0a1b2c3d

    // Service constructors.
    const val C_PING = 0x7abe77ec
    const val C_PONG = 0x347773c5
    const val C_MSGS_ACK = 0x62d6b459
    const val C_BAD_MSG_NOTIFY = 0xa7eff811.toInt()
    const val C_BAD_SERVER_SALT = 0xedab447b.toInt()
    const val C_NEW_SESSION_RESET = 0x9ec20908.toInt()
    const val C_RPC_ERROR = 0x2144ca19
    const val C_RPC_RESULT = 0xf35c6d01.toInt()

    // API constructors.
    const val C_AUTH_BIND = 0x10000001
    const val C_SEND_MESSAGE = 0x10000010
    const val C_GET_HISTORY = 0x10000012
    const val C_GET_DIFFERENCE = 0x10000014
    const val C_READ_HISTORY = 0x10000016
    const val C_SET_TYPING = 0x10000018
    const val C_GET_DIALOGS = 0x10000019
    const val C_UPDATE = 0x10000030
    const val C_OK = 0x10000031

    private const val HEADER_SIZE = 32 // salt(8) session(8) msg_id(8) seq(4) len(4)
    private const val MIN_PADDING = 12
    private const val MAX_PADDING = 1024
    const val MAX_MESSAGE_SIZE = 16 shl 20

    /** msg_id kind, encoded in the low two bits. */
    const val KIND_FROM_CLIENT = 0
    const val KIND_FROM_SERVER_RESPONSE = 1
    const val KIND_FROM_SERVER_PUSH = 3

    // -----------------------------------------------------------------------
    // Payload encoding: a 4-byte constructor id followed by a JSON body
    // -----------------------------------------------------------------------

    fun encodePayload(constructorId: Int, json: String): ByteArray {
        val body = json.toByteArray(Charsets.UTF_8)
        val out = ByteArray(4 + body.size)
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putInt(constructorId)
        body.copyInto(out, 4)
        return out
    }

    fun peekConstructor(payload: ByteArray): Int {
        require(payload.size >= 4) { "mtproto: payload is shorter than a constructor id" }
        return ByteBuffer.wrap(payload, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
    }

    fun decodeBody(payload: ByteArray): String {
        require(payload.size >= 4) { "mtproto: payload is shorter than a constructor id" }
        return String(payload, 4, payload.size - 4, Charsets.UTF_8)
    }

    // -----------------------------------------------------------------------
    // Envelope
    // -----------------------------------------------------------------------

    data class Message(
        val salt: Long,
        val sessionId: Long,
        val msgId: Long,
        val seqNo: Int,
        val body: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Message && salt == other.salt && sessionId == other.sessionId &&
                msgId == other.msgId && seqNo == other.seqNo && body.contentEquals(other.body)

        override fun hashCode(): Int = (salt.hashCode() * 31 + msgId.hashCode()) * 31 + body.contentHashCode()
    }

    /**
     * Builds a wire frame:
     * auth_key_id(8) ‖ msg_key(16) ‖ AES-IGE(header ‖ body ‖ padding)
     */
    fun encrypt(authKey: ByteArray, keyId: ByteArray, msg: Message): ByteArray {
        require(msg.body.size <= MAX_MESSAGE_SIZE) {
            "mtproto: body of ${msg.body.size} bytes exceeds the limit"
        }

        // Padding is 12..1024 bytes taking the total to a 16-byte boundary.
        // Fixed padding would leak the exact body size.
        val unpadded = HEADER_SIZE + msg.body.size
        var pad = MIN_PADDING + (16 - (unpadded + MIN_PADDING) % 16)
        if (pad < MIN_PADDING) pad += 16

        val header = ByteArray(HEADER_SIZE)
        ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(msg.salt)
            putLong(msg.sessionId)
            putLong(msg.msgId)
            putInt(msg.seqNo)
            putInt(msg.body.size)
        }

        val plaintext = Crypto.concat(header, msg.body, Crypto.randomBytes(pad))
        val msgKey = Crypto.msgKey(authKey, plaintext, Crypto.CLIENT_TO_SERVER)
        val (aesKey, aesIv) = Crypto.deriveKeyIV(authKey, msgKey, Crypto.CLIENT_TO_SERVER)

        return Crypto.concat(keyId, msgKey, Crypto.igeEncrypt(aesKey, aesIv, plaintext))
    }

    /** Parses and authenticates a wire frame. */
    fun decrypt(authKey: ByteArray, frame: ByteArray): Message {
        require(frame.size >= 8 + 16 + HEADER_SIZE + MIN_PADDING) { "mtproto: frame is too short" }

        val msgKey = frame.copyOfRange(8, 24)
        val ciphertext = frame.copyOfRange(24, frame.size)
        require(ciphertext.size % 16 == 0) { "mtproto: ciphertext is not block-aligned" }

        val (aesKey, aesIv) = Crypto.deriveKeyIV(authKey, msgKey, Crypto.SERVER_TO_CLIENT)
        val plaintext = Crypto.igeDecrypt(aesKey, aesIv, ciphertext)

        // Authenticate before parsing. Everything below is trusted only
        // because this check passed.
        val expected = Crypto.msgKey(authKey, plaintext, Crypto.SERVER_TO_CLIENT)
        if (!Crypto.constantTimeEquals(expected, msgKey)) {
            throw SecurityException("mtproto: msg_key mismatch (forged, corrupt, or wrong key)")
        }

        val view = ByteBuffer.wrap(plaintext).order(ByteOrder.LITTLE_ENDIAN)
        val salt = view.long
        val sessionId = view.long
        val msgId = view.long
        val seqNo = view.int
        val bodyLen = view.int

        require(bodyLen in 0..MAX_MESSAGE_SIZE && HEADER_SIZE + bodyLen <= plaintext.size) {
            "mtproto: declared body length $bodyLen is invalid"
        }
        val padding = plaintext.size - HEADER_SIZE - bodyLen
        require(padding in MIN_PADDING..MAX_PADDING) {
            "mtproto: padding of $padding bytes is out of range"
        }

        return Message(
            salt, sessionId, msgId, seqNo,
            plaintext.copyOfRange(HEADER_SIZE, HEADER_SIZE + bodyLen),
        )
    }

    /** An unencrypted frame: auth_key_id(0) ‖ msg_id ‖ length ‖ body. */
    fun encodePlain(msgId: Long, body: ByteArray): ByteArray {
        val out = ByteArray(20 + body.size)
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(0L)
            putLong(msgId)
            putInt(body.size)
        }
        body.copyInto(out, 20)
        return out
    }

    data class PlainMessage(val msgId: Long, val body: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is PlainMessage && msgId == other.msgId && body.contentEquals(other.body)

        override fun hashCode(): Int = msgId.hashCode() * 31 + body.contentHashCode()
    }

    fun decodePlain(frame: ByteArray): PlainMessage {
        require(frame.size >= 20) { "mtproto: plain frame is too short" }
        val view = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN)
        require(view.long == 0L) { "mtproto: not a plain message" }

        val msgId = view.long
        val n = view.int
        require(n >= 0 && 20 + n <= frame.size) { "mtproto: declared length exceeds the frame" }

        return PlainMessage(msgId, frame.copyOfRange(20, 20 + n))
    }

    fun peekAuthKeyId(frame: ByteArray): Long {
        require(frame.size >= 8) { "mtproto: frame is too short" }
        return ByteBuffer.wrap(frame, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
    }

    // -----------------------------------------------------------------------
    // Diffie-Hellman
    // -----------------------------------------------------------------------

    /** RFC 3526 MODP group 14: a 2048-bit safe prime with g = 2. */
    private const val DH_PRIME_HEX =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
            "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
            "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
            "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
            "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
            "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
            "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF" +
            "FFFFFFFF"

    val DH_PRIME: BigInteger = BigInteger(DH_PRIME_HEX, 16)
    val DH_G: BigInteger = BigInteger.valueOf(2)
    private val DH_Q: BigInteger = DH_PRIME.subtract(BigInteger.ONE).shiftRight(1)
    private val DH_MARGIN: BigInteger = BigInteger.ONE.shiftLeft(2048 - 64)

    /**
     * Rejects DH values that would collapse the shared secret.
     *
     * Without this a peer forces a shared secret of 0, 1 or p−1 and reads
     * everything afterwards. The margin additionally rules out the
     * small-subgroup and near-boundary tricks.
     */
    fun validateDHValue(v: BigInteger) {
        if (v <= BigInteger.ONE || v >= DH_PRIME.subtract(BigInteger.ONE)) {
            throw IllegalArgumentException("mtproto: the DH value is 0, 1 or p-1")
        }
        if (v < DH_MARGIN) {
            throw IllegalArgumentException("mtproto: the DH value is too close to 0")
        }
        if (v > DH_PRIME.subtract(DH_MARGIN)) {
            throw IllegalArgumentException("mtproto: the DH value is too close to p")
        }
    }

    fun generateExponent(): BigInteger =
        BigInteger(2047, java.security.SecureRandom())
            .mod(DH_Q)
            .add(BigInteger.ONE.shiftLeft(20))

    fun publicValue(x: BigInteger): BigInteger = DH_G.modPow(x, DH_PRIME)

    /** Computes the shared secret, normalised to exactly 256 bytes. */
    fun deriveSharedKey(peerPublic: BigInteger, own: BigInteger): ByteArray {
        validateDHValue(peerPublic)
        return Crypto.toFixedBytes(peerPublic.modPow(own, DH_PRIME), Crypto.AUTH_KEY_SIZE)
    }

    /**
     * The temporary AES key protecting the DH exchange.
     *
     *     key = SHA1(new_nonce ‖ server_nonce) ‖ SHA1(server_nonce ‖ new_nonce)[0..12]
     *     iv  = SHA1(server_nonce ‖ new_nonce)[12..20] ‖ SHA1(new_nonce ‖ new_nonce) ‖ new_nonce[0..4]
     */
    fun tmpAesKeyIv(newNonce: ByteArray, serverNonce: ByteArray): Crypto.KeyIV {
        val ns = Crypto.sha1(newNonce, serverNonce)
        val sn = Crypto.sha1(serverNonce, newNonce)
        val nn = Crypto.sha1(newNonce, newNonce)

        return Crypto.KeyIV(
            key = Crypto.concat(ns, sn.copyOfRange(0, 12)),
            iv = Crypto.concat(sn.copyOfRange(12, 20), nn, newNonce.copyOfRange(0, 4)),
        )
    }

    /** Wraps an inner payload with a SHA-1 prefix and encrypts it. */
    fun igeSeal(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val digest = Crypto.sha1(data)
        var buf = Crypto.concat(digest, data)
        val pad = (16 - buf.size % 16) % 16
        if (pad > 0) buf = Crypto.concat(buf, Crypto.randomBytes(pad))
        return Crypto.igeEncrypt(key, iv, buf)
    }

    /** Reverses igeSeal and verifies the integrity prefix. */
    fun igeOpen(key: ByteArray, iv: ByteArray, sealed: ByteArray): ByteArray {
        val plain = Crypto.igeDecrypt(key, iv, sealed)
        require(plain.size >= 20) { "mtproto: inner data is too short" }

        val digest = plain.copyOfRange(0, 20)
        val body = plain.copyOfRange(20, plain.size)

        // The payload length is unknown because of the padding, so try the
        // candidate lengths from longest to shortest. Padding is at most 15
        // bytes, so this is a bounded scan.
        var cut = body.size
        while (cut >= 0 && body.size - cut <= 16) {
            if (Crypto.constantTimeEquals(Crypto.sha1(body.copyOfRange(0, cut)), digest)) {
                return body.copyOfRange(0, cut)
            }
            cut--
        }
        throw SecurityException("mtproto: inner data integrity check failed")
    }

    /**
     * The fixed 88-byte layout of pq_inner_data.
     *
     * Binary rather than JSON because it must fit in one RSA-OAEP block: a
     * 2048-bit key with SHA-256 OAEP carries at most 190 bytes, and the JSON
     * rendering of three nonces alone exceeds that.
     */
    fun encodePQInnerData(
        pq: Long, p: Long, q: Long,
        nonce: ByteArray, serverNonce: ByteArray, newNonce: ByteArray,
    ): ByteArray {
        val out = ByteArrayOutputStream(88)
        val head = ByteBuffer.allocate(24).order(ByteOrder.BIG_ENDIAN)
        head.putLong(pq).putLong(p).putLong(q)
        out.write(head.array())
        out.write(nonce)
        out.write(serverNonce)
        out.write(newNonce)
        return out.toByteArray()
    }

    /**
     * Factors a semiprime by Pollard's rho — the client's side of the
     * proof of work that gates the expensive DH exchange.
     */
    fun factorPQ(pq: Long): Pair<Long, Long> {
        val n = BigInteger.valueOf(pq)
        if (pq % 2 == 0L) return Pair(2L, pq / 2)

        for (c in 1L until 64L) {
            val cBig = BigInteger.valueOf(c)
            var x = BigInteger.TWO
            var y = BigInteger.TWO
            var d = BigInteger.ONE

            val f = { v: BigInteger -> v.multiply(v).add(cBig).mod(n) }

            var step = 0
            while (step < (1 shl 22)) {
                x = f(x)
                y = f(f(y))
                val diff = x.subtract(y).abs()
                if (diff.signum() == 0) break
                d = diff.gcd(n)
                if (d > BigInteger.ONE) break
                step++
            }

            if (d > BigInteger.ONE && d < n) {
                val a = d.toLong()
                val b = pq / a
                return if (a < b) Pair(a, b) else Pair(b, a)
            }
        }
        throw IllegalArgumentException("mtproto: failed to factor $pq")
    }
}
