package mtproto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestIGERoundTrip(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 32)
	mustRead(t, key)
	mustRead(t, iv)

	for _, size := range []int{16, 32, 64, 256, 1024} {
		plain := make([]byte, size)
		mustRead(t, plain)

		ct, err := IGEEncrypt(key, iv, plain)
		if err != nil {
			t.Fatalf("encrypt %d bytes: %v", size, err)
		}
		if len(ct) != size {
			t.Fatalf("ciphertext length = %d, want %d", len(ct), size)
		}
		if bytes.Equal(ct, plain) {
			t.Fatalf("ciphertext equals plaintext at size %d", size)
		}

		got, err := IGEDecrypt(key, iv, ct)
		if err != nil {
			t.Fatalf("decrypt %d bytes: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round trip mismatch at size %d", size)
		}
	}
}

// TestIGEKnownAnswer pins the mode against a vector produced by the reference
// definition, so a refactor of the chaining cannot silently change the wire
// format and break every deployed client.
func TestIGEKnownAnswer(t *testing.T) {
	// This vector is the widely published AES-128-IGE test case from the
	// original OpenSSL IGE patch: an all-zero key and a 0x00..0x1f IV over a
	// 32-byte all-zero plaintext.
	key, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	iv, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plain, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	want, _ := hex.DecodeString("1A8519A6557BE652E9DA8E43DA4EF4453CF456B4CA488AA383C79C98B34797CB")

	got, err := IGEEncrypt(key, iv, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("IGE known-answer mismatch:\n got %X\nwant %X", got, want)
	}

	back, err := IGEDecrypt(key, iv, want)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("IGE decrypt known-answer mismatch: got %X", back)
	}
}

func TestIGERejectsBadSizes(t *testing.T) {
	key := make([]byte, 32)
	if _, err := IGEEncrypt(key, make([]byte, 16), make([]byte, 32)); !errors.Is(err, ErrIVSize) {
		t.Fatalf("short IV: got %v, want ErrIVSize", err)
	}
	if _, err := IGEEncrypt(key, make([]byte, 32), make([]byte, 17)); !errors.Is(err, ErrBlockSize) {
		t.Fatalf("unaligned data: got %v, want ErrBlockSize", err)
	}
	if _, err := IGEEncrypt(key, make([]byte, 32), nil); !errors.Is(err, ErrBlockSize) {
		t.Fatalf("empty data: got %v, want ErrBlockSize", err)
	}
}

// TestKeyDerivationCrossImplementation pins the KDF against the values the
// TypeScript client produces for the same inputs.
//
// The browser has its own independent implementation (web/lib/mtproto/crypto.ts),
// built on Web Crypto rather than Go's crypto/aes. Two implementations of the
// same specification drifting apart is the failure mode that would silently
// stop every web client decrypting, and neither side's own tests would catch
// it. The same vector is asserted in web/lib/mtproto/crypto.test.mjs.
func TestKeyDerivationCrossImplementation(t *testing.T) {
	raw := make([]byte, AuthKeySize)
	for i := range raw {
		raw[i] = byte((i * 13) & 0xff)
	}
	key, err := NewAuthKey(raw)
	if err != nil {
		t.Fatalf("new auth key: %v", err)
	}

	body := []byte("the quick brown fox")

	const (
		wantMsgKey = "93065c239f68031c3bb889e26ef945cd"
		wantAESKey = "1d3eed336606b3bb23b7e2eb98f0052222dd6b62bd5f9910f50139fa7128bd30"
		wantAESIV  = "924933f8f370ea91b725878863320ef5db29e5ef4291089972c4d94fe54688ff"
	)

	mk := key.MsgKey(body, ClientToServer)
	if got := hex.EncodeToString(mk); got != wantMsgKey {
		t.Fatalf("msg_key = %s, want %s\n(the Go and TypeScript implementations have diverged)", got, wantMsgKey)
	}

	aesKey, aesIV, err := key.DeriveAESKeyIV(mk, ClientToServer)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got := hex.EncodeToString(aesKey); got != wantAESKey {
		t.Fatalf("aes_key = %s, want %s", got, wantAESKey)
	}
	if got := hex.EncodeToString(aesIV); got != wantAESIV {
		t.Fatalf("aes_iv = %s, want %s", got, wantAESIV)
	}
}

func TestKeyDerivationDirectionsDiffer(t *testing.T) {
	key := newTestAuthKey(t)
	plain := []byte("the quick brown fox jumps over the lazy dog12345")

	c2s := key.MsgKey(plain, ClientToServer)
	s2c := key.MsgKey(plain, ServerToClient)
	if bytes.Equal(c2s, s2c) {
		t.Fatal("msg_key is identical in both directions; the x offset is not applied")
	}

	kc, ivc, err := key.DeriveAESKeyIV(c2s, ClientToServer)
	if err != nil {
		t.Fatalf("derive c2s: %v", err)
	}
	ks, ivs, err := key.DeriveAESKeyIV(c2s, ServerToClient)
	if err != nil {
		t.Fatalf("derive s2c: %v", err)
	}
	if bytes.Equal(kc, ks) || bytes.Equal(ivc, ivs) {
		t.Fatal("AES key schedule is identical in both directions")
	}
	if len(kc) != 32 || len(ivc) != 32 {
		t.Fatalf("key/iv sizes = %d/%d, want 32/32", len(kc), len(ivc))
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	key := newTestAuthKey(t)

	for _, size := range []int{0, 1, 15, 16, 17, 4096} {
		body := make([]byte, size)
		mustRead(t, body)

		in := &Message{Salt: 0x1122334455667788, SessionID: 0x0badc0de, MsgID: nowMsgID(), SeqNo: 3, Body: body}
		frame, err := Encrypt(key, in, ClientToServer)
		if err != nil {
			t.Fatalf("encrypt body of %d: %v", size, err)
		}

		// The envelope must be a whole number of AES blocks after the header.
		if (len(frame)-authKeyIDSize-msgKeySize)%16 != 0 {
			t.Fatalf("ciphertext is not block-aligned for body size %d", size)
		}

		gotID, err := PeekAuthKeyID(frame)
		if err != nil || gotID != key.ID() {
			t.Fatalf("peek auth key id = %x (%v), want %x", gotID, err, key.ID())
		}

		out, err := Decrypt(key, frame, ClientToServer)
		if err != nil {
			t.Fatalf("decrypt body of %d: %v", size, err)
		}
		if out.Salt != in.Salt || out.SessionID != in.SessionID ||
			out.MsgID != in.MsgID || out.SeqNo != in.SeqNo {
			t.Fatalf("header mismatch: %+v vs %+v", out, in)
		}
		if !bytes.Equal(out.Body, body) {
			t.Fatalf("body mismatch at size %d", size)
		}
	}
}

func TestEnvelopeRejectsTampering(t *testing.T) {
	key := newTestAuthKey(t)
	in := &Message{Salt: 1, SessionID: 2, MsgID: nowMsgID(), SeqNo: 1, Body: []byte("hello world")}

	frame, err := Encrypt(key, in, ClientToServer)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Flip a bit deep inside the ciphertext. IGE garbles everything from that
	// block onwards, so the recomputed msg_key must not match.
	tampered := bytes.Clone(frame)
	tampered[len(tampered)-5] ^= 0x01
	if _, err := Decrypt(key, tampered, ClientToServer); !errors.Is(err, ErrBadMsgKey) {
		t.Fatalf("tampered ciphertext: got %v, want ErrBadMsgKey", err)
	}

	// Flip a bit in msg_key itself.
	tampered = bytes.Clone(frame)
	tampered[authKeyIDSize] ^= 0x80
	if _, err := Decrypt(key, tampered, ClientToServer); err == nil {
		t.Fatal("tampered msg_key was accepted")
	}

	// Decrypting with the wrong direction must fail: this is what stops a
	// reflected message from being accepted.
	if _, err := Decrypt(key, frame, ServerToClient); err == nil {
		t.Fatal("frame decrypted in the wrong direction")
	}

	// A frame produced under a different key must be rejected by id.
	other := newTestAuthKey(t)
	if _, err := Decrypt(other, frame, ClientToServer); !errors.Is(err, ErrUnknownAuthKey) {
		t.Fatalf("wrong key: got %v, want ErrUnknownAuthKey", err)
	}
}

func TestPlainMessageRoundTrip(t *testing.T) {
	body := []byte(`{"nonce":"abc"}`)
	frame := EncodePlain(0x1234, body)

	if id, err := PeekAuthKeyID(frame); err != nil || id != 0 {
		t.Fatalf("plain frame auth key id = %x (%v), want 0", id, err)
	}
	msgID, got, err := DecodePlain(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msgID != 0x1234 || !bytes.Equal(got, body) {
		t.Fatalf("plain round trip mismatch: %x %q", msgID, got)
	}
	if _, _, err := DecodePlain(frame[:10]); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("short plain frame: got %v, want ErrShortFrame", err)
	}
}

func TestMsgIDGeneratorIsMonotonic(t *testing.T) {
	var g MsgIDGenerator
	prev := int64(0)
	for i := 0; i < 10_000; i++ {
		id := g.Next(KindFromServerResponse)
		if id <= prev {
			t.Fatalf("msg_id went backwards at %d: %d <= %d", i, id, prev)
		}
		if id&3 != KindFromServerResponse {
			t.Fatalf("msg_id %d has the wrong kind bits", id)
		}
		prev = id
	}
}

func TestMsgIDValidator(t *testing.T) {
	v := NewMsgIDValidator()

	valid := nowMsgID()
	if err := v.Check(valid); err != nil {
		t.Fatalf("fresh msg_id rejected: %v", err)
	}
	if err := v.Check(valid); !errors.Is(err, ErrMsgIDReplay) {
		t.Fatalf("replay: got %v, want ErrMsgIDReplay", err)
	}

	old := (time.Now().Add(-10*time.Minute).Unix() << 32)
	if err := v.Check(old); !errors.Is(err, ErrMsgIDTooOld) {
		t.Fatalf("old msg_id: got %v, want ErrMsgIDTooOld", err)
	}

	future := (time.Now().Add(10*time.Minute).Unix() << 32)
	if err := v.Check(future); !errors.Is(err, ErrMsgIDTooNew) {
		t.Fatalf("future msg_id: got %v, want ErrMsgIDTooNew", err)
	}

	if err := v.Check(nowMsgID() | 1); !errors.Is(err, ErrMsgIDParity) {
		t.Fatalf("odd client msg_id: got %v, want ErrMsgIDParity", err)
	}
}

func TestSeqNoCounter(t *testing.T) {
	var c SeqNoCounter
	if got := c.Next(false); got != 0 {
		t.Fatalf("first service seq_no = %d, want 0", got)
	}
	if got := c.Next(true); got != 1 {
		t.Fatalf("first content seq_no = %d, want 1", got)
	}
	if got := c.Next(false); got != 2 {
		t.Fatalf("service seq_no after one content message = %d, want 2", got)
	}
	if got := c.Next(true); got != 3 {
		t.Fatalf("second content seq_no = %d, want 3", got)
	}
}

func TestPQFactorisation(t *testing.T) {
	for i := 0; i < 20; i++ {
		pq, p, q, err := GeneratePQ()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if p*q != pq || p >= q {
			t.Fatalf("generated bad semiprime: %d * %d != %d", p, q, pq)
		}
		gotP, gotQ, err := FactorPQ(pq)
		if err != nil {
			t.Fatalf("factor %d: %v", pq, err)
		}
		if gotP != p || gotQ != q {
			t.Fatalf("factor(%d) = %d,%d want %d,%d", pq, gotP, gotQ, p, q)
		}
		if err := VerifyPQ(pq, gotP, gotQ); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
	if err := VerifyPQ(15, 1, 15); !errors.Is(err, ErrNotFactors) {
		t.Fatalf("trivial factors accepted: %v", err)
	}
	if err := VerifyPQ(15, 3, 4); !errors.Is(err, ErrNotFactors) {
		t.Fatalf("wrong factors accepted: %v", err)
	}
}

// TestHandshakeEndToEnd drives both halves of the negotiation and asserts the
// two sides derive byte-identical auth keys.
func TestHandshakeEndToEnd(t *testing.T) {
	serverKey, pubPEM := newTestServerKey(t)

	server := NewServerHandshake(serverKey, 30*time.Second)
	client, err := NewClientHandshake(pubPEM)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	reqPQ, err := client.Start()
	if err != nil {
		t.Fatalf("client start: %v", err)
	}
	resPQ, err := server.ReqPQ(reqPQ.Nonce)
	if err != nil {
		t.Fatalf("server req_pq: %v", err)
	}

	reqDH, err := client.OnResPQ(resPQ)
	if err != nil {
		t.Fatalf("client res_pq: %v", err)
	}
	serverDH, err := server.ReqDHParams(reqDH)
	if err != nil {
		t.Fatalf("server req_dh_params: %v", err)
	}

	setDH, err := client.OnServerDHParams(serverDH)
	if err != nil {
		t.Fatalf("client server_dh_params: %v", err)
	}
	serverAuthKey, genOK, err := server.SetClientDHParams(setDH)
	if err != nil {
		t.Fatalf("server set_client_dh_params: %v", err)
	}
	if !server.Done() {
		t.Fatal("server handshake did not complete")
	}

	clientAuthKey, err := client.OnDHGenOK(genOK)
	if err != nil {
		t.Fatalf("client dh_gen_ok: %v", err)
	}

	if !bytes.Equal(serverAuthKey.Bytes(), clientAuthKey.Bytes()) {
		t.Fatal("client and server derived different auth keys")
	}
	if serverAuthKey.ID() != clientAuthKey.ID() {
		t.Fatalf("auth key ids differ: %x vs %x", serverAuthKey.ID(), clientAuthKey.ID())
	}
	if len(serverAuthKey.Bytes()) != AuthKeySize {
		t.Fatalf("auth key is %d bytes, want %d", len(serverAuthKey.Bytes()), AuthKeySize)
	}

	// And the negotiated key must actually work for message traffic.
	msg := &Message{Salt: 7, SessionID: 9, MsgID: nowMsgID(), SeqNo: 1, Body: []byte("post-handshake")}
	frame, err := Encrypt(clientAuthKey, msg, ClientToServer)
	if err != nil {
		t.Fatalf("encrypt with negotiated key: %v", err)
	}
	out, err := Decrypt(serverAuthKey, frame, ClientToServer)
	if err != nil {
		t.Fatalf("decrypt with negotiated key: %v", err)
	}
	if string(out.Body) != "post-handshake" {
		t.Fatalf("body = %q", out.Body)
	}
}

func TestHandshakeRejectsWrongNonce(t *testing.T) {
	serverKey, pubPEM := newTestServerKey(t)
	server := NewServerHandshake(serverKey, 30*time.Second)
	client, _ := NewClientHandshake(pubPEM)

	reqPQ, _ := client.Start()
	resPQ, _ := server.ReqPQ(reqPQ.Nonce)
	reqDH, err := client.OnResPQ(resPQ)
	if err != nil {
		t.Fatalf("client res_pq: %v", err)
	}

	reqDH.Nonce[0] ^= 0xFF
	if _, err := server.ReqDHParams(reqDH); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("tampered nonce: got %v, want ErrNonceMismatch", err)
	}
}

func TestHandshakeRejectsBadFactors(t *testing.T) {
	serverKey, pubPEM := newTestServerKey(t)
	server := NewServerHandshake(serverKey, 30*time.Second)
	client, _ := NewClientHandshake(pubPEM)

	reqPQ, _ := client.Start()
	resPQ, _ := server.ReqPQ(reqPQ.Nonce)
	reqDH, _ := client.OnResPQ(resPQ)

	reqDH.P, reqDH.Q = 3, 5 // does not multiply to pq
	if _, err := server.ReqDHParams(reqDH); !errors.Is(err, ErrNotFactors) {
		t.Fatalf("bad proof of work: got %v, want ErrNotFactors", err)
	}
}

func TestHandshakeRejectsOutOfOrderSteps(t *testing.T) {
	serverKey, _ := newTestServerKey(t)
	server := NewServerHandshake(serverKey, 30*time.Second)

	if _, err := server.ReqDHParams(ReqDHParams{}); !errors.Is(err, ErrHandshakeState) {
		t.Fatalf("step 3 before step 1: got %v, want ErrHandshakeState", err)
	}
	if _, _, err := server.SetClientDHParams(SetClientDHParams{}); !errors.Is(err, ErrHandshakeState) {
		t.Fatalf("step 5 before step 3: got %v, want ErrHandshakeState", err)
	}
}

func TestDHValueValidation(t *testing.T) {
	initDH()
	cases := map[string]string{
		"zero":    "0",
		"one":     "1",
		"two":     "2",
		"p_minus": DHPrime().Sub(DHPrime(), bigOne()).String(),
	}
	for name, dec := range cases {
		v := mustBig(t, dec)
		if err := validateDHValue(v); !errors.Is(err, ErrBadDHValue) {
			t.Fatalf("%s: got %v, want ErrBadDHValue", name, err)
		}
	}
	// A legitimate value derived from the generator must pass.
	good := DHPrime()
	good.Rsh(good, 1) // roughly p/2, comfortably inside the safe band
	if err := validateDHValue(good); err != nil {
		t.Fatalf("valid DH value rejected: %v", err)
	}
}

func TestTLEncodeDecode(t *testing.T) {
	in := SendMessage{ChatID: 42, Type: "text", Body: "hi", RandomID: 99}
	payload, err := Encode(CSendMessage, in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	id, err := PeekConstructor(payload)
	if err != nil || id != CSendMessage {
		t.Fatalf("peek = %#x (%v), want %#x", id, err, CSendMessage)
	}
	var out SendMessage
	if err := Decode(payload, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
	if _, err := PeekConstructor([]byte{1, 2}); !errors.Is(err, ErrShortPayload) {
		t.Fatalf("short payload: got %v, want ErrShortPayload", err)
	}
}

func TestAuthKeyIDIsStable(t *testing.T) {
	raw := make([]byte, AuthKeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	a, err := NewAuthKey(raw)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	b, _ := NewAuthKey(raw)
	if a.ID() != b.ID() {
		t.Fatal("auth key id is not deterministic")
	}
	if len(a.IDHex()) != 16 {
		t.Fatalf("id hex = %q, want 16 characters", a.IDHex())
	}
	if _, err := NewAuthKey(raw[:100]); err == nil {
		t.Fatal("short auth key accepted")
	}

	a.Zero()
	for _, v := range a.Bytes() {
		if v != 0 {
			t.Fatal("Zero did not wipe the key material")
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustRead(t *testing.T, b []byte) {
	t.Helper()
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
}

func newTestAuthKey(t *testing.T) *AuthKey {
	t.Helper()
	raw := make([]byte, AuthKeySize)
	mustRead(t, raw)
	k, err := NewAuthKey(raw)
	if err != nil {
		t.Fatalf("new auth key: %v", err)
	}
	return k
}

func newTestServerKey(t *testing.T) (*ServerKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))

	sk, err := LoadServerKey(privPEM)
	if err != nil {
		t.Fatalf("load server key: %v", err)
	}
	pubPEM, err := sk.PublicPEM()
	if err != nil {
		t.Fatalf("public PEM: %v", err)
	}
	return sk, pubPEM
}

func nowMsgID() int64 { return time.Now().Unix() << 32 }
