# DID-Encryption SDK (Swift)

Swift implementation of the NDA-focused proxy re-encryption workflow.

This package lets you:

- Encrypt data for a data owner (Alice) and create a `capsule`.
- Re-encrypt that capsule for a delegate (Bob) via a `reCapsule`.
- Let Bob decrypt using his own private key.
- Support both single-message and chunked stream encryption.

## Package

- Library product: `DIDEncrypt`
- Minimum platforms:
  - iOS 13+
  - macOS 12+

## Installation

Use the monorepo URL with a release tag:

```swift
.package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", from: "1.0.0")
```

Then add the product to your target:

```swift
.product(name: "DIDEncrypt", package: "nda-sfs-sdk")
```

## Tagging For Swift Release (Monorepo)

SwiftPM resolves this SDK from the repository root `Package.swift`, so publish a
normal semver tag at repo level (not a folder-prefixed tag):

```bash
git tag v1.0.0
git push origin v1.0.0
```

Then client apps can consume with:

```swift
.package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", from: "1.0.0")
```

If this monorepo also publishes Go modules, you can still keep Go submodule tags
separately (for example `did-encryption/v1.0.0`) without affecting SwiftPM.

## Quick Start (Single Message)

```swift
import Foundation
import DIDEncrypt

let alice = try DIDEncrypt.generateKeys()
let bob = try DIDEncrypt.generateKeys()

let message = Data("NDA DID Encryption with Swift".utf8)

// 1) Create encryptor for Alice (chunkSize = 0 means non-stream mode)
let (encryptor, capsule) = try DIDEncrypt.newEncryptor(
    ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex,
    chunkSize: 0
)

// 2) Alice encrypts
let ciphertext = try encryptor.encrypt(message)

// 3) Alice creates re-capsule for Bob
let reCapsule = try DIDEncrypt.createReCapsule(
    ownerPrivateKeyHex: alice.privateKeyHex,
    receiverPublicKeyCompressedHex: bob.publicKeyCompressedHex,
    capsule: capsule
)

// 4) Bob creates decryptor and decrypts
let bobDecryptor = try DIDEncrypt.newDecryptor(
    receiverPrivateKeyHex: bob.privateKeyHex,
    reCapsule: reCapsule
)
let plaintext = try bobDecryptor.decrypt(ciphertext)

print(String(data: plaintext, encoding: .utf8) ?? "")
```

## Decryptor Serialization

```swift
// Serialize
let hex = bobDecryptor.hex()

// Deserialize
let restored = try Decryptor.fromHex(hex)

// Use it
let plaintext = try restored.decrypt(ciphertext)
```

## Owner Decryption

```swift
let ownerDecryptor = try DIDEncrypt.newDecryptorByOwner(
    ownerPrivateKeyHex: alice.privateKeyHex,
    capsule: capsule
)

let ownerPlaintext = try ownerDecryptor.decryptByOwner(ciphertext)
```

## Stream Encryption / Decryption

Set `chunkSize > 0` to enable stream mode.

```swift
import Foundation
import DIDEncrypt

let alice = try DIDEncrypt.generateKeys()
let bob = try DIDEncrypt.generateKeys()

let content = Data(repeating: 0x41, count: 1024 * 128)

let (encryptor, capsule) = try DIDEncrypt.newEncryptor(
    ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex,
    chunkSize: 64 * 1024
)

let inStream = InputStream(data: content)
let outStream = OutputStream.toMemory()
try encryptor.encryptStream(input: inStream, output: outStream)
let encrypted = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

let reCapsule = try DIDEncrypt.createReCapsule(
    ownerPrivateKeyHex: alice.privateKeyHex,
    receiverPublicKeyCompressedHex: bob.publicKeyCompressedHex,
    capsule: capsule
)

let bobDecryptor = try DIDEncrypt.newDecryptor(
    receiverPrivateKeyHex: bob.privateKeyHex,
    reCapsule: reCapsule
)

let decIn = InputStream(data: encrypted)
let decOut = OutputStream.toMemory()
try bobDecryptor.decryptStream(input: decIn, output: decOut)
let decrypted = decOut.property(forKey: .dataWrittenToMemoryStreamKey) as! Data

print(decrypted == content) // true
```

## API Summary

- `DIDEncrypt.generateKeys()`
- `DIDEncrypt.newEncryptor(ownerPublicKeyCompressedHex:chunkSize:)`
- `DIDEncrypt.createReCapsule(ownerPrivateKeyHex:receiverPublicKeyCompressedHex:capsule:)`
- `DIDEncrypt.newDecryptor(receiverPrivateKeyHex:reCapsule:)`
- `DIDEncrypt.newDecryptorByOwner(ownerPrivateKeyHex:capsule:)`
- `Encryptor.encrypt(_:)`
- `Encryptor.encryptStream(input:output:)`
- `Decryptor.decrypt(_:)`
- `Decryptor.decryptByOwner(_:)`
- `Decryptor.decryptStream(input:output:)`
- `Decryptor.hex()`
- `Decryptor.fromHex(_:)`

## Notes

- `chunkSize = 0` means single-message mode.
- `chunkSize > 0` means stream mode.
- `capsule` length is `185` bytes.
- `reCapsule` length is `250` bytes.

## Testing

```bash
cd did-encryption-swift
swift test --enable-swift-testing --disable-xctest
```
