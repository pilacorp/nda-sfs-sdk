# DID-Encryption SDK (Swift)

Swift implementation of the NDA-focused proxy re-encryption workflow.

## What It Does

- Encrypts data for an owner and produces a `capsule`
- Re-encrypts that `capsule` for a delegate as a `reCapsule`
- Lets the delegate decrypt with their own private key
- Supports single-message and chunked stream encryption

## Package

- Library product: `DIDEncrypt`
- Minimum platforms:
  - iOS 13+
  - macOS 12+

## Client Usage

Add the SDK to your app with a release tag:

```swift
.package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", from: "1.0.1")
```

Then add the product to your target:

```swift
.product(name: "DIDEncrypt", package: "nda-sfs-sdk")
```

## Release Tag

This Swift package is resolved from the repository root `Package.swift`.
Publish a root tag for the release:

```bash
git tag v1.0.1
git push origin v1.0.1
```

Client apps should consume it with:

```swift
.package(url: "https://github.com/pilacorp/nda-sfs-sdk.git", from: "1.0.1")
```

Do not use folder-prefixed tags for SwiftPM consumption. SwiftPM reads the root
package manifest and expects normal semver release tags.

## Quick Start

```swift
import Foundation
import DIDEncrypt

let alice = try DIDEncrypt.generateKeys()
let bob = try DIDEncrypt.generateKeys()
let message = Data("NDA DID Encryption with Swift".utf8)

let (encryptor, capsule) = try DIDEncrypt.newEncryptor(
    ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex,
    chunkSize: 0
)

let ciphertext = try encryptor.encrypt(message)

let reCapsule = try DIDEncrypt.createReCapsule(
    ownerPrivateKeyHex: alice.privateKeyHex,
    receiverPublicKeyCompressedHex: bob.publicKeyCompressedHex,
    capsule: capsule
)

let bobDecryptor = try DIDEncrypt.newDecryptor(
    receiverPrivateKeyHex: bob.privateKeyHex,
    reCapsule: reCapsule
)

let plaintext = try bobDecryptor.decrypt(ciphertext)
print(String(data: plaintext, encoding: .utf8) ?? "")
```

## Stream Mode

Set `chunkSize > 0` for stream mode:

```swift
let (encryptor, capsule) = try DIDEncrypt.newEncryptor(
    ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex,
    chunkSize: 64 * 1024
)
```

Use `encryptStream(input:output:)` and `decryptStream(input:output:)` for the
streaming path.

## Decryptor Serialization

Warning: `Decryptor.hex()` serializes secret key material. Only use it for
controlled local persistence, never for logs, telemetry, or transport.

```swift
let hex = bobDecryptor.hex()
let restored = try Decryptor.fromHex(hex)
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

- `chunkSize = 0` means single-message mode
- `chunkSize > 0` means stream mode
- `capsule` length is `185` bytes
- `reCapsule` length is `250` bytes

## Testing

```bash
cd did-encryption-swift
swift test --enable-swift-testing --disable-xctest
```
