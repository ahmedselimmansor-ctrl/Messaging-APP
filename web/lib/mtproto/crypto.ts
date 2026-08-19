/**
 * MTProto cryptography in the browser.
 *
 * The interesting constraint: Web Crypto does not expose AES-ECB, and IGE is
 * built from raw block operations. The way through is that a single-block
 * AES-CBC encryption with a zero IV *is* an ECB block encryption — so the
 * block primitive is recovered without shipping a JavaScript AES
 * implementation, and the actual cipher work stays in the browser's native,
 * constant-time code.
 *
 * This mirrors pkg/mtproto in the Go server. The two must agree byte for
 * byte, so any change here needs the same change there.
 */

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/**
 * A byte array backed by a plain ArrayBuffer.
 *
 * TypeScript 5.7 made Uint8Array generic over its buffer, and the unadorned
 * `Uint8Array` widens to `ArrayBufferLike` — which includes SharedArrayBuffer
 * and is therefore not assignable to Web Crypto's BufferSource. Pinning it
 * here keeps every signature in this package precise instead of casting at
 * each call site.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

export function concat(...parts: Bytes[]): Bytes {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function randomBytes(n: number): Bytes {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function equalConstantTime(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  // Accumulate rather than returning early: an early return leaks how many
  // leading bytes matched, which is enough to forge a value one byte at a
  // time.
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(b: Bytes): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s: string): Bytes {
  const clean = s.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function utf8(s: string): Bytes {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Bytes): string {
  return new TextDecoder().decode(b);
}

// ---------------------------------------------------------------------------
// AES block primitive
// ---------------------------------------------------------------------------

const ZERO_IV = new Uint8Array(16);

/** Writes a ⊕ b into dst. All three are one AES block. */
function xorInto(dst: Bytes, a: Bytes, b: Bytes): void {
  for (let i = 0; i < 16; i++) dst[i] = a[i]! ^ b[i]!;
}


/**
 * Encrypts exactly one 16-byte block.
 *
 * AES-CBC with a zero IV over a single block is identical to AES-ECB over
 * that block. Web Crypto always appends a PKCS#7 padding block, so the result
 * is 32 bytes and only the first 16 are the block we asked for.
 */
async function encryptBlock(key: CryptoKey, block: Bytes): Promise<Bytes> {
  const out = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ZERO_IV }, key, block);
  return new Uint8Array(out, 0, 16);
}

/**
 * Decrypts exactly one 16-byte block.
 *
 * Decryption is the harder direction: Web Crypto insists on validating PKCS#7
 * padding, so a bare block cannot be handed to it. The way through is to
 * append a second ciphertext block engineered so that CBC decryption produces
 * valid padding for it.
 *
 * CBC decryption gives p2 = D(c2) ⊕ c1, and we want p2 to be the all-0x10
 * block PKCS#7 appends to an already-aligned message. Solving for c2:
 *
 *     c2 = E(0x10…10 ⊕ c1)
 *
 * where c1 is the block being decrypted. The first output block is then
 * p1 = D(c1) ⊕ IV = D(c1) — the raw ECB decryption we wanted.
 *
 * The obvious construction, appending E(0x10…10) with no XOR, decrypts to
 * padding ⊕ c1 and fails validation for every non-zero block.
 */
async function decryptBlock(key: CryptoKey, block: Bytes): Promise<Bytes> {
  const padding = new Uint8Array(16).fill(16);
  const target = new Uint8Array(16);
  xorInto(target, padding, block);

  const trailer = await encryptBlock(key, target);

  const out = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: ZERO_IV },
    key,
    concat(block, trailer),
  );
  return new Uint8Array(out, 0, 16);
}

async function importAESKey(raw: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-CBC" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// ---------------------------------------------------------------------------
// AES-IGE
// ---------------------------------------------------------------------------

/**
 * AES-256-IGE encryption.
 *
 *   y[i] = E(x[i] ⊕ y[i-1]) ⊕ x[i-1]
 *
 * with y[-1] and x[-1] from the first and second halves of the 32-byte IV.
 */
export async function igeEncrypt(
  keyBytes: Bytes,
  iv: Bytes,
  data: Bytes,
): Promise<Bytes> {
  if (iv.length !== 32) throw new Error("mtproto: IGE IV must be 32 bytes");
  if (data.length === 0 || data.length % 16 !== 0) {
    throw new Error("mtproto: IGE data must be a non-empty multiple of 16 bytes");
  }

  const key = await importAESKey(keyBytes);
  const out = new Uint8Array(data.length);

  let prevCipher = iv.slice(0, 16);
  let prevPlain = iv.slice(16, 32);
  const buf = new Uint8Array(16);

  for (let i = 0; i < data.length; i += 16) {
    const plain = data.subarray(i, i + 16);
    xorInto(buf, plain, prevCipher);
    const encrypted = await encryptBlock(key, buf);
    const block = out.subarray(i, i + 16);
    xorInto(block, encrypted, prevPlain);

    prevCipher = block.slice();
    prevPlain = plain.slice();
  }
  return out;
}

/**
 * AES-256-IGE decryption.
 *
 *   x[i] = D(y[i] ⊕ x[i-1]) ⊕ y[i-1]
 */
export async function igeDecrypt(
  keyBytes: Bytes,
  iv: Bytes,
  data: Bytes,
): Promise<Bytes> {
  if (iv.length !== 32) throw new Error("mtproto: IGE IV must be 32 bytes");
  if (data.length === 0 || data.length % 16 !== 0) {
    throw new Error("mtproto: IGE data must be a non-empty multiple of 16 bytes");
  }

  const key = await importAESKey(keyBytes);
  const out = new Uint8Array(data.length);

  let prevCipher = iv.slice(0, 16);
  let prevPlain = iv.slice(16, 32);
  const buf = new Uint8Array(16);

  for (let i = 0; i < data.length; i += 16) {
    const ciph = data.subarray(i, i + 16);
    xorInto(buf, ciph, prevPlain);
    const decrypted = await decryptBlock(key, buf);
    const block = out.subarray(i, i + 16);
    xorInto(block, decrypted, prevCipher);

    prevCipher = ciph.slice();
    prevPlain = block.slice();
  }
  return out;
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

export async function sha256(...parts: Bytes[]): Promise<Bytes> {
  const digest = await crypto.subtle.digest("SHA-256", concat(...parts));
  return new Uint8Array(digest);
}

export async function sha1(...parts: Bytes[]): Promise<Bytes> {
  // SHA-1 here is an identifier and part of MTProto's specified handshake
  // KDF, never a security primitive on its own.
  const digest = await crypto.subtle.digest("SHA-1", concat(...parts));
  return new Uint8Array(digest);
}

// ---------------------------------------------------------------------------
// MTProto 2.0 key derivation
// ---------------------------------------------------------------------------

/** Direction selects which half of the key schedule to use. */
export const CLIENT_TO_SERVER = 0;
export const SERVER_TO_CLIENT = 8;

export const AUTH_KEY_SIZE = 256;

/**
 * msg_key = substr(SHA256(substr(auth_key, 88 + x, 32) ‖ plaintext), 8, 16)
 *
 * Because the digest covers a secret slice of the auth key, only a key holder
 * can produce a valid msg_key — this is what authenticates the message.
 */
export async function msgKey(
  authKey: Bytes,
  plaintext: Bytes,
  x: number,
): Promise<Bytes> {
  const digest = await sha256(authKey.subarray(88 + x, 88 + x + 32), plaintext);
  return digest.subarray(8, 24);
}

/**
 * Derives the per-message AES key and IV.
 *
 * The interleave of the two digests is deliberate: neither alone determines
 * the key, so leaking one does not hand over the key schedule.
 */
export async function deriveKeyIV(
  authKey: Bytes,
  msgKeyBytes: Bytes,
  x: number,
): Promise<{ key: Bytes; iv: Bytes }> {
  const a = await sha256(msgKeyBytes, authKey.subarray(x, x + 36));
  const b = await sha256(authKey.subarray(40 + x, 40 + x + 36), msgKeyBytes);

  const key = concat(a.subarray(0, 8), b.subarray(8, 24), a.subarray(24, 32));
  const iv = concat(b.subarray(0, 8), a.subarray(8, 24), b.subarray(24, 32));
  return { key, iv };
}

/** The 64-bit auth key identifier: substr(SHA1(auth_key), 12, 8). */
export async function authKeyID(authKey: Bytes): Promise<Bytes> {
  const digest = await sha1(authKey);
  return digest.subarray(12, 20);
}

// ---------------------------------------------------------------------------
// Big integers
// ---------------------------------------------------------------------------

export function bytesToBigInt(b: Bytes): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

export function bigIntToBytes(v: bigint, size?: number): Bytes {
  let hex = v.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let bytes = fromHex(hex);

  if (size !== undefined) {
    if (bytes.length > size) {
      bytes = bytes.subarray(bytes.length - size);
    } else if (bytes.length < size) {
      // Left-pad. A shared secret with leading zero bytes would otherwise
      // produce a short auth key and the two sides would derive different
      // keys.
      const padded = new Uint8Array(size);
      padded.set(bytes, size - bytes.length);
      bytes = padded;
    }
  }
  return bytes;
}

/** Modular exponentiation by square-and-multiply. */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/** A cryptographically random bigint below `max`. */
export function randomBigInt(max: bigint): bigint {
  const bytes = (max.toString(16).length + 1) >> 1;
  // Rejection sampling: a modulo would bias the low end.
  for (;;) {
    const v = bytesToBigInt(randomBytes(bytes));
    if (v > 0n && v < max) return v;
  }
}
