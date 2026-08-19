# Android client — MTProto module

The third implementation of the platform's protocol, alongside `pkg/mtproto`
(Go, server and reference client) and `web/lib/mtproto` (TypeScript, browser).

## Why it is a plain JVM module

`mtproto` has no Android dependencies. It uses only `java.security` and
`java.math`, both of which exist unchanged on Android. That means its tests
run under a normal JVM test task — no emulator, no device — so the
cross-implementation vectors run on every CI build instead of being something
someone remembers to check.

## The vectors that matter

`CryptoTest` pins the same values asserted in `pkg/mtproto/mtproto_test.go`
and `web/lib/mtproto/crypto.test.mjs`:

| | |
|---|---|
| AES-IGE known answer | `1a8519a6…b34797cb` (the published OpenSSL IGE vector) |
| `msg_key` | `93065c239f68031c3bb889e26ef945cd` |
| `aes_key` | `1d3eed33…7128bd30` |
| `aes_iv` | `924933f8…e54688ff` |

Three independent implementations of one specification will drift apart
eventually. Pinning the same values in all three turns that drift into a build
failure rather than an Android client that silently cannot decrypt anything —
a failure neither the server's tests nor the browser's would ever catch.

## Building

With Gradle:

```bash
./gradlew :mtproto:test
```

Without Gradle — what CI does, and what works on a machine with only a JDK and
`kotlinc`:

```bash
make android-test
```

from the repository root.

## What is here, and what is not

Present: AES-IGE, the MTProto 2.0 key derivation, the message envelope, the
Diffie-Hellman group with its safety checks, the handshake's inner-data
sealing, and the `pq` proof-of-work factorisation.

Absent: the UI, the connection manager, local message storage, and the
notification integration. Those belong to the app, and the app is not in this
repository — see the "What is not built" section of the root README.
