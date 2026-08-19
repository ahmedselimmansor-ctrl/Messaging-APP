// Package mtproto implements the realtime protocol spoken between clients and
// the realtime gateway.
//
// # What is faithful to MTProto 2.0
//
//   - AES-256 in IGE mode, with Telegram's exact block chaining (ige.go).
//   - The msg_key / key-derivation construction: msg_key is bytes 8..24 of
//     SHA-256 over a 32-byte slice of the auth key followed by the plaintext,
//     and aes_key/aes_iv are interleaved from two further SHA-256 digests,
//     with the x=0 / x=8 split that gives each direction its own keys
//     (keys.go).
//   - The encrypted message envelope: auth_key_id ‖ msg_key ‖ AES-IGE(salt ‖
//     session_id ‖ msg_id ‖ seq_no ‖ length ‖ body ‖ padding), padding 12..1024
//     bytes to a 16-byte boundary (message.go).
//   - msg_id semantics: unix time in the high 32 bits, monotonic within a
//     session, low two bits encoding the message kind; replay and
//     out-of-window rejection (message.go).
//   - The auth-key handshake: req_pq with a proof-of-work semiprime
//     factorisation, RSA-wrapped new_nonce, 2048-bit Diffie-Hellman, and the
//     tmp_aes_key/tmp_aes_iv derivation from new_nonce and server_nonce
//     (handshake.go, pq.go).
//   - The three transport framings — abridged, intermediate and padded
//     intermediate — and the obfuscation2 AES-CTR wrapper (codec/).
//
// # Where this deliberately differs
//
// The RPC payload is *not* TL-serialised. A method call is a 4-byte
// constructor id followed by a JSON body (tl.go). Telegram's TL schema is a
// large, generated, version-locked artefact; carrying a hand-written subset
// of it would be a permanent maintenance cost for no benefit to a platform
// whose clients we also write. Everything above the payload boundary is
// unchanged, so swapping in a real TL codec later means replacing exactly one
// file.
//
// The consequence, stated plainly: an official Telegram client cannot talk to
// this server, and this is not a Telegram-compatible implementation. It is a
// messaging protocol built on MTProto's cryptographic and transport design.
//
// The Diffie-Hellman group is RFC 3526 MODP group 14 (2048-bit safe prime,
// g=2) rather than Telegram's own prime — a published, widely reviewed group
// with the same security properties.
//
// # Layering
//
//	transport/   framing and I/O over TCP, UDP or WebSocket
//	codec/       abridged | intermediate | padded-intermediate | obfuscated2
//	message.go   the encrypted envelope and msg_id rules
//	keys.go      auth keys and key derivation
//	ige.go       the block cipher mode
//	handshake.go auth key negotiation
//	tl.go        RPC payload encoding
package mtproto
