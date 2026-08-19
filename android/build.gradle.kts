// Android client for the messaging platform.
//
// The `mtproto` module is a pure-JVM library with no Android dependencies at
// all. That is deliberate: it means the protocol implementation runs under a
// plain JVM test task in CI, with no emulator and no device, which is what
// makes the cross-implementation vectors in CryptoTest actually run on every
// build rather than being aspirational.

plugins {
    kotlin("jvm") version "2.1.0" apply false
    id("com.android.application") version "8.7.3" apply false
    id("com.android.library") version "8.7.3" apply false
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
