/**
 * Cross-implementation tests for the browser crypto.
 *
 * The point of this file is not to test AES — the browser does that. It is to
 * catch the browser implementation and the Go server implementation drifting
 * apart, which would silently stop every web client decrypting and which
 * neither side's own tests would notice.
 *
 * The same vectors are asserted in pkg/mtproto/mtproto_test.go. If a change to
 * either side breaks one of these, it breaks both, loudly.
 *
 * Run with: npm test
 *
 * The module under test is TypeScript, so it is compiled to a scratch
 * directory first — see the `test` script in package.json.
 */

import test from "node:test";
import assert from "node:assert/strict";

const {
  igeEncrypt,
  igeDecrypt,
  fromHex,
  toHex,
  msgKey,
  deriveKeyIV,
  authKeyID,
  equalConstantTime,
  bytesToBigInt,
  bigIntToBytes,
  modPow,
} = await import("../../.test-build/crypto.js");

test("AES-IGE matches the published known-answer vector", async () => {
  // The AES-128-IGE test case from the original OpenSSL IGE patch. The Go
  // implementation pins the same one.
  const key = fromHex("000102030405060708090A0B0C0D0E0F");
  const iv = fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
  const plain = fromHex("0000000000000000000000000000000000000000000000000000000000000000");
  const want = "1a8519a6557be652e9da8e43da4ef4453cf456b4ca488aa383c79c98b34797cb";

  const got = await igeEncrypt(key, iv, plain);
  assert.equal(toHex(got), want, "IGE encryption diverged from the reference vector");

  const back = await igeDecrypt(key, iv, got);
  assert.equal(toHex(back), toHex(plain), "IGE decryption did not invert encryption");
});

test("AES-256-IGE round trips at several sizes", async () => {
  const key = new Uint8Array(32).map((_, i) => i);
  const iv = new Uint8Array(32).map((_, i) => 255 - i);

  for (const size of [16, 32, 256, 4096]) {
    const data = new Uint8Array(size).map((_, i) => (i * 7) & 0xff);
    const ct = await igeEncrypt(key, iv, data);
    assert.equal(ct.length, size);
    assert.notEqual(toHex(ct), toHex(data), "ciphertext equals plaintext");

    const pt = await igeDecrypt(key, iv, ct);
    assert.equal(toHex(pt), toHex(data), `round trip failed at ${size} bytes`);
  }
});

test("AES-IGE rejects malformed input", async () => {
  const key = new Uint8Array(32);
  await assert.rejects(() => igeEncrypt(key, new Uint8Array(16), new Uint8Array(32)));
  await assert.rejects(() => igeEncrypt(key, new Uint8Array(32), new Uint8Array(17)));
  await assert.rejects(() => igeEncrypt(key, new Uint8Array(32), new Uint8Array(0)));
});

test("the key derivation matches the Go server byte for byte", async () => {
  // Identical inputs and expected outputs to
  // TestKeyDerivationCrossImplementation in pkg/mtproto/mtproto_test.go.
  const authKey = new Uint8Array(256).map((_, i) => (i * 13) & 0xff);
  const body = new TextEncoder().encode("the quick brown fox");

  const mk = await msgKey(authKey, body, 0);
  assert.equal(
    toHex(mk),
    "93065c239f68031c3bb889e26ef945cd",
    "msg_key diverged from the Go implementation",
  );

  const { key, iv } = await deriveKeyIV(authKey, mk, 0);
  assert.equal(
    toHex(key),
    "1d3eed336606b3bb23b7e2eb98f0052222dd6b62bd5f9910f50139fa7128bd30",
    "aes_key diverged from the Go implementation",
  );
  assert.equal(
    toHex(iv),
    "924933f8f370ea91b725878863320ef5db29e5ef4291089972c4d94fe54688ff",
    "aes_iv diverged from the Go implementation",
  );
});

test("each direction gets its own key schedule", async () => {
  const authKey = new Uint8Array(256).map((_, i) => (i * 13) & 0xff);
  const body = new TextEncoder().encode("payload");

  const c2s = await msgKey(authKey, body, 0);
  const s2c = await msgKey(authKey, body, 8);
  assert.notEqual(toHex(c2s), toHex(s2c), "the x offset is not being applied");

  const a = await deriveKeyIV(authKey, c2s, 0);
  const b = await deriveKeyIV(authKey, c2s, 8);
  assert.notEqual(toHex(a.key), toHex(b.key));
  assert.notEqual(toHex(a.iv), toHex(b.iv));
  assert.equal(a.key.length, 32);
  assert.equal(a.iv.length, 32);
});

test("the auth key id is the low 64 bits of SHA-1", async () => {
  const authKey = new Uint8Array(256).map((_, i) => i & 0xff);
  const id = await authKeyID(authKey);
  assert.equal(id.length, 8);

  const again = await authKeyID(authKey);
  assert.equal(toHex(id), toHex(again), "the key id is not deterministic");
});

test("the constant-time comparison is correct", () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  assert.equal(equalConstantTime(a, new Uint8Array([1, 2, 3, 4])), true);
  assert.equal(equalConstantTime(a, new Uint8Array([1, 2, 3, 5])), false);
  assert.equal(equalConstantTime(a, new Uint8Array([9, 2, 3, 4])), false);
  assert.equal(equalConstantTime(a, new Uint8Array([1, 2, 3])), false);
});

test("big integer conversion left-pads to a fixed width", () => {
  // A shared secret with leading zero bytes must still produce a 256-byte
  // auth key, or the two sides derive different keys.
  const small = 255n;
  const padded = bigIntToBytes(small, 256);
  assert.equal(padded.length, 256);
  assert.equal(padded[255], 255);
  assert.equal(padded[0], 0);
  assert.equal(bytesToBigInt(padded), small);
});

test("modular exponentiation is correct", () => {
  assert.equal(modPow(2n, 10n, 1000n), 24n);
  assert.equal(modPow(3n, 0n, 7n), 1n);
  // A value large enough that a naive implementation would overflow.
  const p = (1n << 127n) - 1n;
  assert.equal(modPow(2n, p - 1n, p), 1n); // Fermat's little theorem
});
