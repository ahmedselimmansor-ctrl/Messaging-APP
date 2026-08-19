plugins {
    kotlin("jvm")
}

// No Android dependency on purpose — see the comment in the root build file.
// Everything here is java.security and java.math, which exist on both the JVM
// and Android.

kotlin {
    jvmToolchain(17)
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
