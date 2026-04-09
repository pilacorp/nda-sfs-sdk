import Foundation
import Testing
@testable import DIDEncrypt

private func expectDIDError(
    _ expected: DIDEncryptError,
    _ block: () throws -> Void
) {
    do {
        try block()
        #expect(Bool(false), "Expected error \(expected), but no error was thrown")
    } catch let err as DIDEncryptError {
        #expect(err == expected)
    } catch {
        #expect(Bool(false), "Expected DIDEncryptError \(expected), got \(error)")
    }
}

@Test func e2e() throws {
    let alice = try DIDEncrypt.generateKeys()
    let bob = try DIDEncrypt.generateKeys()

    let message = Data("Hello, World! This is a test message for proxy re-encryption.".utf8)

    let (enc, capsule) = try DIDEncrypt.newEncryptor(ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex, chunkSize: 0)
    let cipher = try enc.encrypt(message)

    let reCapsule = try DIDEncrypt.createReCapsule(
        ownerPrivateKeyHex: alice.privateKeyHex,
        receiverPublicKeyCompressedHex: bob.publicKeyCompressedHex,
        capsule: capsule
    )

    let bobDec = try DIDEncrypt.newDecryptor(receiverPrivateKeyHex: bob.privateKeyHex, reCapsule: reCapsule)
    let bobHex = bobDec.hex()
    let bobDec2 = try Decryptor.fromHex(bobHex)
    #expect(bobHex == bobDec2.hex())

    let plain = try bobDec2.decrypt(cipher)
    #expect(plain == message)

    let aliceDec = try DIDEncrypt.newDecryptorByOwner(ownerPrivateKeyHex: alice.privateKeyHex, capsule: capsule)
    let alicePlain = try aliceDec.decryptByOwner(cipher)
    #expect(alicePlain == message)
}

@Test func e2eStream() throws {
    let alice = try DIDEncrypt.generateKeys()
    let bob = try DIDEncrypt.generateKeys()

    let message = Data("Hello, World! This is a test message for proxy re-encryption.".utf8)

    let (enc, capsule) = try DIDEncrypt.newEncryptor(ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex, chunkSize: 2)

    let inStream = InputStream(data: message)
    let outStream = OutputStream.toMemory()
    try enc.encryptStream(input: inStream, output: outStream)

    guard let encrypted = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
        throw DIDEncryptError.truncatedStream
    }

    let reCapsule = try DIDEncrypt.createReCapsule(
        ownerPrivateKeyHex: alice.privateKeyHex,
        receiverPublicKeyCompressedHex: bob.publicKeyCompressedHex,
        capsule: capsule
    )

    let bobDec = try DIDEncrypt.newDecryptor(receiverPrivateKeyHex: bob.privateKeyHex, reCapsule: reCapsule)
    let decIn = InputStream(data: encrypted)
    let decOut = OutputStream.toMemory()
    try bobDec.decryptStream(input: decIn, output: decOut)

    guard let decrypted = decOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
        throw DIDEncryptError.truncatedStream
    }
    #expect(decrypted == message)

    let aliceDec = try DIDEncrypt.newDecryptorByOwner(ownerPrivateKeyHex: alice.privateKeyHex, capsule: capsule)
    let ownerIn = InputStream(data: encrypted)
    let ownerOut = OutputStream.toMemory()
    try aliceDec.decryptStream(input: ownerIn, output: ownerOut)

    guard let ownerDecrypted = ownerOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
        throw DIDEncryptError.truncatedStream
    }
    #expect(ownerDecrypted == message)
}

@Test func invalidCapsuleLengths() throws {
    let owner = try DIDEncrypt.generateKeys()
    let receiver = try DIDEncrypt.generateKeys()

    expectDIDError(.invalidLength(expected: 185, actual: 10)) {
        _ = try DIDEncrypt.newDecryptorByOwner(
            ownerPrivateKeyHex: owner.privateKeyHex,
            capsule: Data(repeating: 0, count: 10)
        )
    }

    expectDIDError(.invalidLength(expected: 250, actual: 10)) {
        _ = try DIDEncrypt.newDecryptor(
            receiverPrivateKeyHex: receiver.privateKeyHex,
            reCapsule: Data(repeating: 0, count: 10)
        )
    }
}

@Test func wrongModeGuards() throws {
    let owner = try DIDEncrypt.generateKeys()
    let message = Data("mode-check".utf8)

    // stream encryptor should reject non-stream encrypt()
    let (streamEnc, streamCapsule) = try DIDEncrypt.newEncryptor(
        ownerPublicKeyCompressedHex: owner.publicKeyCompressedHex,
        chunkSize: 16
    )
    expectDIDError(.streamModeNotAllowed) {
        _ = try streamEnc.encrypt(message)
    }

    let ownerDecStream = try DIDEncrypt.newDecryptorByOwner(
        ownerPrivateKeyHex: owner.privateKeyHex,
        capsule: streamCapsule
    )
    expectDIDError(.streamModeNotAllowed) {
        _ = try ownerDecStream.decrypt(message)
    }

    // non-stream encryptor/decryptor should reject stream APIs
    let (singleEnc, singleCapsule) = try DIDEncrypt.newEncryptor(
        ownerPublicKeyCompressedHex: owner.publicKeyCompressedHex,
        chunkSize: 0
    )
    expectDIDError(.chunkSizeNotSet) {
        try singleEnc.encryptStream(input: InputStream(data: message), output: OutputStream.toMemory())
    }

    let ownerDecSingle = try DIDEncrypt.newDecryptorByOwner(
        ownerPrivateKeyHex: owner.privateKeyHex,
        capsule: singleCapsule
    )
    expectDIDError(.chunkSizeNotSet) {
        try ownerDecSingle.decryptStream(input: InputStream(data: message), output: OutputStream.toMemory())
    }
}

@Test func tamperedCiphertextFails() throws {
    let owner = try DIDEncrypt.generateKeys()
    let message = Data("tamper-check-ciphertext".utf8)

    let (enc, capsule) = try DIDEncrypt.newEncryptor(
        ownerPublicKeyCompressedHex: owner.publicKeyCompressedHex,
        chunkSize: 0
    )
    let ciphertext = try enc.encrypt(message)
    let dec = try DIDEncrypt.newDecryptorByOwner(ownerPrivateKeyHex: owner.privateKeyHex, capsule: capsule)

    var tampered = ciphertext
    tampered[tampered.count - 1] ^= 0x01

    do {
        _ = try dec.decryptByOwner(tampered)
        Issue.record("Expected decrypt failure for tampered ciphertext")
    } catch {
        // expected
    }
}

@Test func tamperedReCapsuleFails() throws {
    let alice = try DIDEncrypt.generateKeys()
    let bob = try DIDEncrypt.generateKeys()

    let (_, capsule) = try DIDEncrypt.newEncryptor(
        ownerPublicKeyCompressedHex: alice.publicKeyCompressedHex,
        chunkSize: 0
    )
    let reCapsule = try DIDEncrypt.createReCapsule(
        ownerPrivateKeyHex: alice.privateKeyHex,
        receiverPublicKeyCompressedHex: bob.publicKeyCompressedHex,
        capsule: capsule
    )

    var tampered = reCapsule
    tampered[10] ^= 0x01

    do {
        _ = try DIDEncrypt.newDecryptor(receiverPrivateKeyHex: bob.privateKeyHex, reCapsule: tampered)
        Issue.record("Expected newDecryptor failure for tampered reCapsule")
    } catch {
        // expected
    }
}

@Test func decryptorHexValidation() throws {
    expectDIDError(.invalidHex) {
        _ = try Decryptor.fromHex("zz")
    }

    expectDIDError(.invalidLength(expected: 48, actual: 2)) {
        _ = try Decryptor.fromHex("0001")
    }
}
