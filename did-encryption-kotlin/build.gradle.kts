plugins {
    kotlin("jvm") version "2.1.20"
}

group = "io.pilacorp"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Bouncy Castle: secp256k1 elliptic curve + SHA3-256
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(11)
}

tasks.test {
    useJUnitPlatform()
}
