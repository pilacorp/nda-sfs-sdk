import Foundation
import BigInt
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

private func fixedPrivateKey(_ byte: UInt8) throws -> Secp256k1PrivateKey {
    try Secp256k1PrivateKey(raw32: Data(repeating: byte, count: 32))
}

private func logStep(_ name: String, _ value: String) {
    print("STEP|\(name)|\(value)")
}

private func logStep(_ name: String, _ value: Data) {
    logStep(name, value.didEncryptHexString)
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

@Test func malformedCapsuleFieldsFail() throws {
    let owner = try DIDEncrypt.generateKeys()

    let (_, capsule) = try DIDEncrypt.newEncryptor(
        ownerPublicKeyCompressedHex: owner.publicKeyCompressedHex,
        chunkSize: 0
    )

    var malformed = capsule
    malformed[0] = 31
    expectDIDError(.invalidCapsule) {
        _ = try DIDEncrypt.newDecryptorByOwner(ownerPrivateKeyHex: owner.privateKeyHex, capsule: malformed)
    }
}

@Test func oversizedChunkSizeIsRejected() throws {
    let owner = try DIDEncrypt.generateKeys()
    expectDIDError(.chunkSizeOutOfRange) {
        _ = try DIDEncrypt.newEncryptor(
            ownerPublicKeyCompressedHex: owner.publicKeyCompressedHex,
            chunkSize: didEncryptMaxChunkSize + 1
        )
    }
}

@Test func nonStreamEncryptionUsesFreshNonce() throws {
    let owner = try DIDEncrypt.generateKeys()
    let message = Data("nonce-check".utf8)

    let (enc, capsule) = try DIDEncrypt.newEncryptor(
        ownerPublicKeyCompressedHex: owner.publicKeyCompressedHex,
        chunkSize: 0
    )

    let first = try enc.encrypt(message)
    let second = try enc.encrypt(message)
    #expect(first != second)

    let dec = try DIDEncrypt.newDecryptorByOwner(ownerPrivateKeyHex: owner.privateKeyHex, capsule: capsule)
    #expect(try dec.decrypt(first) == message)
    #expect(try dec.decrypt(second) == message)
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

@Test func deterministicParityVector() throws {
    let ownerPriv = try fixedPrivateKey(0x11)
    let receiverPriv = try fixedPrivateKey(0x22)
    let encryptEPriv = try fixedPrivateKey(0x33)
    let encryptVPriv = try fixedPrivateKey(0x44)
    let rekeyXPriv = try fixedPrivateKey(0x55)

    let ownerPub = try Secp256k1PublicKey(uncompressed65: ownerPriv.publicKeyUncompressed())
    let receiverPub = try Secp256k1PublicKey(uncompressed65: receiverPriv.publicKeyUncompressed())
    let encryptEPub = try Secp256k1PublicKey(uncompressed65: encryptEPriv.publicKeyUncompressed())
    let encryptVPub = try Secp256k1PublicKey(uncompressed65: encryptVPriv.publicKeyUncompressed())
    let rekeyXPub = try Secp256k1PublicKey(uncompressed65: rekeyXPriv.publicKeyUncompressed())

    let message = Data("Cross-language deterministic test payload.".utf8)
    let chunkSize: UInt32 = 16

    logStep("ownerPrivateKey", ownerPriv.raw32)
    logStep("ownerPublicKey", try ownerPub.compressed33())
    logStep("receiverPrivateKey", receiverPriv.raw32)
    logStep("receiverPublicKey", try receiverPub.compressed33())
    logStep("encryptEPrivateKey", encryptEPriv.raw32)
    logStep("encryptEPublicKey", try encryptEPub.compressed33())
    logStep("encryptVPrivateKey", encryptVPriv.raw32)
    logStep("encryptVPublicKey", try encryptVPub.compressed33())
    logStep("rekeyXPrivateKey", rekeyXPriv.raw32)
    logStep("rekeyXPublicKey", try rekeyXPub.compressed33())
    logStep("plaintext", message)

    let h = hashToCurveScalar(concat(encryptEPub.uncompressed65, encryptVPub.uncompressed65))
    let encryptEInt = BigUInt.fromBigEndian(encryptEPriv.raw32)
    let encryptVInt = BigUInt.fromBigEndian(encryptVPriv.raw32)
    let ownerInt = BigUInt.fromBigEndian(ownerPriv.raw32)

    let s = modNAdd(encryptVInt, modNMul(encryptEInt, h))
    let sum = modNAdd(encryptEInt, encryptVInt).toBigEndian(minBytes: 32)
    let sharedPoint = try pointMul(ownerPub, scalar32: sum)
    let keyBytes = sha3_256(sharedPoint.uncompressed65)
    let capsuleSingle = Capsule(E: encryptEPub, V: encryptVPub, S: s, chunkSize: 0, version: 0)
    let capsuleStream = Capsule(E: encryptEPub, V: encryptVPub, S: s, chunkSize: chunkSize, version: 0)
    let capsuleSingleBytes = encodeCapsule(capsuleSingle)
    let capsuleStreamBytes = encodeCapsule(capsuleStream)

    logStep("capsuleSingle", capsuleSingleBytes)
    logStep("capsuleStream", capsuleStreamBytes)
    logStep("aesKey", keyBytes.prefix(32))
    logStep("baseNonce", keyBytes.prefix(12))

    let nonce12 = Data(keyBytes.prefix(12))
    let singleCipher = try aesGcmEncrypt(plaintext: message, key32: Data(keyBytes.prefix(32)), nonce12: nonce12)
    logStep("singleCiphertext", singleCipher)
    #expect(try aesGcmDecrypt(ciphertextAndTag: singleCipher, key32: Data(keyBytes.prefix(32)), nonce12: nonce12) == message)

    let pointX = try pointMul(receiverPub, scalar32: rekeyXPriv.raw32)
    let d = hashToCurveScalar(
        concat(
            concat(rekeyXPub.uncompressed65, receiverPub.uncompressed65),
            pointX.uncompressed65
        )
    )
    let rk = modNMul(ownerInt, try modNInverse(d))
    let reCapsuleSingle = try reEncrypt(rk: rk, capsule: capsuleSingle)
    let reCapsuleStream = try reEncrypt(rk: rk, capsule: capsuleStream)
    let reCapsuleSingleBytes = encodeCapsule(reCapsuleSingle) + rekeyXPub.uncompressed65
    let reCapsuleStreamBytes = encodeCapsule(reCapsuleStream) + rekeyXPub.uncompressed65

    logStep("reCapsuleSingle", reCapsuleSingleBytes)
    logStep("reCapsuleStream", reCapsuleStreamBytes)

    let receiverPlain = try aesGcmDecrypt(
        ciphertextAndTag: singleCipher,
        key32: Data(keyBytes.prefix(32)),
        nonce12: nonce12
    )
    let ownerPlain = try aesGcmDecrypt(
        ciphertextAndTag: singleCipher,
        key32: Data(keyBytes.prefix(32)),
        nonce12: nonce12
    )
    logStep("receiverPlaintext", receiverPlain)
    logStep("ownerPlaintext", ownerPlain)
    #expect(receiverPlain == message)
    #expect(ownerPlain == message)

    let streamEncryptor = Encryptor(
        aesKey32: Data(keyBytes.prefix(32)),
        baseNonce12: Data(keyBytes.prefix(12)),
        chunkSize: chunkSize
    )
    let streamInput = InputStream(data: message)
    let streamOutput = OutputStream.toMemory()
    try streamEncryptor.encryptStream(input: streamInput, output: streamOutput)
    guard let streamCipher = streamOutput.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
        throw DIDEncryptError.truncatedStream
    }
    logStep("streamCiphertext", streamCipher)

    let receiverDecryptorStream = try DIDEncrypt.newDecryptor(
        receiverPrivateKeyHex: receiverPriv.raw32.didEncryptHexString,
        reCapsule: reCapsuleStreamBytes
    )
    let ownerDecryptorStream = try DIDEncrypt.newDecryptorByOwner(
        ownerPrivateKeyHex: ownerPriv.raw32.didEncryptHexString,
        capsule: capsuleStreamBytes
    )

    let receiverStreamOut = OutputStream.toMemory()
    try receiverDecryptorStream.decryptStream(input: InputStream(data: streamCipher), output: receiverStreamOut)
    guard let receiverStreamPlain = receiverStreamOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
        throw DIDEncryptError.truncatedStream
    }

    let ownerStreamOut = OutputStream.toMemory()
    try ownerDecryptorStream.decryptStream(input: InputStream(data: streamCipher), output: ownerStreamOut)
    guard let ownerStreamPlain = ownerStreamOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
        throw DIDEncryptError.truncatedStream
    }

    logStep("receiverStreamPlaintext", receiverStreamPlain)
    logStep("ownerStreamPlaintext", ownerStreamPlain)
    #expect(receiverStreamPlain == message)
    #expect(ownerStreamPlain == message)
}
