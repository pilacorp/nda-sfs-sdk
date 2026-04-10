# did-encryption (Kotlin)

A Kotlin/JVM port of the [`did-encryption`](../did-encryption) Go package.  
Implements **Proxy Re-Encryption (PRE)** over the **secp256k1** elliptic curve, combined with **AES-256-GCM** symmetric encryption.  
This allows a data owner (Alice) to encrypt data once, then delegate decryption rights to another party (Bob) without re-encrypting the data or revealing the original private key.

---

## How it works

```
Alice encrypts:
  (Encryptor, capsule) = Encryptor.create(alicePubKey)
  cipherText           = encryptor.encrypt(data)

Alice delegates to Bob:
  shareKey = createReCapsule(alicePrivKey, bobPubKey, capsule)

Bob decrypts:
  decryptor = Decryptor.create(bobPrivKey, shareKey)
  plainText = decryptor.decrypt(cipherText)

Alice decrypts (as owner):
  decryptor = Decryptor.createByOwner(alicePrivKey, capsule)
  plainText = decryptor.decryptByOwner(cipherText)
```

---

## Requirements

| Tool | Version |
|------|---------|
| JDK  | 11+     |
| Kotlin | 1.9+  |
| Gradle | 8.7+ (or Maven 3.6+) |

**Runtime dependency:** [Bouncy Castle](https://www.bouncycastle.org/) `bcprov-jdk18on:1.78.1` — used for secp256k1 curve operations and SHA3-256.

---

## Building

### Gradle

```bash
# Generate the Gradle wrapper (first time only — requires Gradle installed)
gradle wrapper

# Compile and run tests
./gradlew test

# Build a JAR
./gradlew jar
# Output: build/libs/did-encryption-1.0.0.jar
```

### Maven

```bash
mvn test       # compile and run tests
mvn package    # build JAR → target/did-encryption-1.0.0.jar
```

---

## Installation in another project

### Option 1 — JitPack (recommended, no setup required)

Add JitPack as a repository and declare the dependency. Replace `TAG` with a Git tag like `v1.0.0` or use `main-SNAPSHOT` for the latest commit.

**Gradle (Kotlin DSL):**

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven { url = uri("https://jitpack.io") }
    }
}
```

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.github.YOUR_GITHUB_USERNAME.nda-sfs-sdk:did-encryption:TAG")
}
```

**Gradle (Groovy):**

```groovy
// settings.gradle
dependencyResolutionManagement {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```

```groovy
// build.gradle
dependencies {
    implementation 'com.github.YOUR_GITHUB_USERNAME.nda-sfs-sdk:did-encryption:TAG'
}
```

**Maven:**

```xml
<!-- pom.xml -->
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.github.YOUR_GITHUB_USERNAME.nda-sfs-sdk</groupId>
        <artifactId>did-encryption</artifactId>
        <version>TAG</version>
    </dependency>
</dependencies>
```

> **First use**: JitPack builds the package on the first request. Visit  
> `https://jitpack.io/#YOUR_GITHUB_USERNAME/nda-sfs-sdk` to pre-trigger the build and check the build log.

---

### Option 2 — Install to local Maven repository

```bash
# Maven (from the did-encryption-kotlin directory)
mvn install

# Gradle
./gradlew publishToMavenLocal
```

Then reference it locally:

```kotlin
// build.gradle.kts
repositories {
    mavenLocal()
    mavenCentral()
}
dependencies {
    implementation("io.pilacorp:did-encryption:1.0.0")
}
```

### Option 3 — File dependency (JAR)

Build the JAR and copy it into your project's `libs/` folder:

```bash
mvn package   # → target/did-encryption-1.0.0.jar
```

```kotlin
// build.gradle.kts
dependencies {
    implementation(files("libs/did-encryption-1.0.0.jar"))
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")  // required transitive dep
}
```

---

## Usage

### Basic (single-shot) encryption

```kotlin
import io.pilacorp.didencryption.didencrypt.Decryptor
import io.pilacorp.didencryption.didencrypt.Encryptor
import io.pilacorp.didencryption.didencrypt.createReCapsule
import io.pilacorp.didencryption.utils.*

// Generate key pairs
val (alicePriv, alicePub) = generateKeys()
val (bobPriv,   bobPub)   = generateKeys()

val message = "Hello, PRE!".toByteArray()

// 1. Alice creates an encryptor and encrypts data
val (encryptor, capsule) = Encryptor.create(
    pubKey    = publicKeyToCompressedKey(alicePub),
    chunkSize = 0   // 0 = single-shot (non-stream) mode
)
val cipherText = encryptor.encrypt(message)

// 2. Alice creates a re-capsule for Bob (can be sent to a proxy)
val shareKey = createReCapsule(
    ownerPrvKey    = privateKeyToHexString(alicePriv),
    receiverPubKey = publicKeyToCompressedKey(bobPub),
    capsule        = capsule
)

// 3. Bob decrypts using the share key and his private key
val bobDecryptor = Decryptor.create(
    receiverPrvKey = privateKeyToHexString(bobPriv),
    reCapsule      = shareKey
)
val plainText = bobDecryptor.decrypt(cipherText)
println(String(plainText)) // → "Hello, PRE!"

// 4. Alice decrypts as the original owner
val aliceDecryptor = Decryptor.createByOwner(
    ownerPrvKey = privateKeyToHexString(alicePriv),
    capsule     = capsule
)
println(String(aliceDecryptor.decryptByOwner(cipherText))) // → "Hello, PRE!"
```

### Serializing a Decryptor (for storage or transport)

```kotlin
// Serialize to hex string
val hex = bobDecryptor.toHex()  // 96 hex chars (48 bytes)

// Reconstruct later
val restored = Decryptor.fromHex(hex)
val plainText = restored.decrypt(cipherText)
```

### Stream encryption (large files)

Use `chunkSize > 0` to encrypt/decrypt in fixed-size chunks. Each chunk gets a unique nonce derived from a counter, preventing nonce-reuse attacks.

```kotlin
import java.io.FileInputStream
import java.io.FileOutputStream

val chunkSize = 64 * 1024  // 64 KiB per chunk

// Encrypt
val (encryptor, capsule) = Encryptor.create(
    pubKey    = publicKeyToCompressedKey(alicePub),
    chunkSize = chunkSize
)
encryptor.encryptStream(
    input  = FileInputStream("plaintext.bin"),
    output = FileOutputStream("encrypted.bin")
)

// Delegate and decrypt
val shareKey  = createReCapsule(privateKeyToHexString(alicePriv), publicKeyToCompressedKey(bobPub), capsule)
val decryptor = Decryptor.create(privateKeyToHexString(bobPriv), shareKey)
decryptor.decryptStream(
    input  = FileInputStream("encrypted.bin"),
    output = FileOutputStream("recovered.bin")
)
```

### Working with raw key strings

```kotlin
// Parse an existing hex private key (with or without 0x prefix)
val privKey = privateKeyStrToKey("0xabc123...")
val privKey = privateKeyStrToKey("abc123...")

// Convert back to hex
val hexStr = privateKeyToHexString(privKey)  // 64 hex chars (32 bytes, zero-padded)

// Compressed public key (33 bytes → 66 hex chars)
val pubHex = publicKeyToCompressedKey(pubKey)
val pubKey = publicCompressedKeyToKey(pubHex)
```

---

## Package structure

```
io.pilacorp.didencryption
├── curve
│   ├── Curve.kt       — Secp256k1 singleton, point arithmetic (add, mul, G*k)
│   └── CurveMath.kt   — Modular arithmetic mod N (add, sub, mul, invert)
├── utils
│   ├── KeyUtils.kt    — Key generation, hex serialization/deserialization
│   └── HashUtils.kt   — SHA3-256 hash, byte concatenation, hash-to-curve
└── didencrypt
    ├── AesGcm.kt      — AES-256-GCM encrypt/decrypt primitives
    ├── Capsule.kt     — Capsule data class, binary encode/decode
    ├── Encryptor.kt   — Encryptor (single-shot + stream)
    ├── Decryptor.kt   — Decryptor (single-shot + stream + hex serialization)
    └── Recrypt.kt     — PRE core: key generation, re-encryption, createReCapsule
```

---

## Binary formats

### Capsule (185 bytes)

Produced by `Encryptor.create` and stored by the owner.

| Field | Type | Size |
|-------|------|------|
| len(E.X) | uint32 LE | 4 |
| E.X | bytes | ≤32 |
| len(E.Y) | uint32 LE | 4 |
| E.Y | bytes | ≤32 |
| len(V.X) | uint32 LE | 4 |
| V.X | bytes | ≤32 |
| len(V.Y) | uint32 LE | 4 |
| V.Y | bytes | ≤32 |
| len(S)   | uint32 LE | 4 |
| S        | bytes | ≤32 |
| chunkSize | uint32 LE | 4 |
| version   | uint8    | 1 |

### Re-capsule (250 bytes)

Produced by `createReCapsule` and given to the delegate.

| Field | Size |
|-------|------|
| Re-encrypted capsule | 185 bytes |
| Ephemeral public key X (uncompressed) | 65 bytes |

### Decryptor hex (96 chars = 48 bytes)

Produced by `Decryptor.toHex()`.

| Field | Size |
|-------|------|
| AES key | 32 bytes |
| Base nonce | 12 bytes |
| chunkSize (uint32 LE) | 4 bytes |

---

## Go interoperability

This library is **wire-compatible** with the Go `did-encryption` package. A capsule or re-capsule produced by the Go library can be decrypted by this Kotlin library and vice versa, provided both use the same key material.

Key parity notes:

| Concern | Go | Kotlin |
|---------|-----|--------|
| Curve | `go-ethereum` secp256k1 | Bouncy Castle secp256k1 |
| Hash | `golang.org/x/crypto/sha3` → SHA3-256 (NIST) | Bouncy Castle `SHA3Digest(256)` |
| Uncompressed point | `crypto.FromECDSAPub` → 65 bytes | `ECPoint.getEncoded(false)` → 65 bytes |
| Compressed point | `crypto.CompressPubkey` → 33 bytes | `ECPoint.getEncoded(true)` → 33 bytes |
| AES-GCM tag | 128 bits (16 bytes) | `GCMParameterSpec(128, ...)` |
| Endianness | Little-endian length prefixes | `ByteBuffer.LITTLE_ENDIAN` |
| Stream nonce counter | Big-endian uint32 at bytes [8..11] | `ByteBuffer` default (big-endian) |

---

## License

Same license as the parent `nda-sfs-sdk` repository.
