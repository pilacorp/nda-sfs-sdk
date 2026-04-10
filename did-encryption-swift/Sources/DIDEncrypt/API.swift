import Foundation
import BigInt

public struct DIDEncrypt {
    public static func generateKeys() throws -> (privateKeyHex: String, publicKeyCompressedHex: String) {
        let priv = try Secp256k1PrivateKey.generate()
        let pub = try Secp256k1PublicKey(uncompressed65: priv.publicKeyUncompressed())
        return (priv.raw32.didEncryptHexString, try pub.compressed33().didEncryptHexString)
    }

    public static func newEncryptor(ownerPublicKeyCompressedHex: String, chunkSize: UInt32) throws -> (encryptor: Encryptor, capsule: Data) {
        guard chunkSize == 0 || chunkSize <= didEncryptMaxChunkSize else {
            throw DIDEncryptError.chunkSizeOutOfRange
        }
        let pubData = try ownerPublicKeyCompressedHex.didEncryptHexData()
        let ownerPub = try Secp256k1PublicKey.fromCompressed(pubData)
        let (cap, keyBytes) = try generateAESKey(ownerPub: ownerPub, chunkSize: chunkSize)
        let capsuleBytes = encodeCapsule(cap)

        let aesKey32 = Data(keyBytes.prefix(32))
        let baseNonce12 = Data(keyBytes.prefix(12))
        return (Encryptor(aesKey32: aesKey32, baseNonce12: baseNonce12, chunkSize: chunkSize), capsuleBytes)
    }

    public static func createReCapsule(ownerPrivateKeyHex: String, receiverPublicKeyCompressedHex: String, capsule: Data) throws -> Data {
        let ownerPriv = try Secp256k1PrivateKey(raw32: try ownerPrivateKeyHex.didEncryptHexData().normalizedPrivateKeyBytes())
        let recvPub = try Secp256k1PublicKey.fromCompressed(try receiverPublicKeyCompressedHex.didEncryptHexData())

        let cap = try decodeCapsule(capsule)
        let (rk, pubX) = try rekeyGenerate(ownerPriv: ownerPriv, receiverPub: recvPub)
        let reCap = try reEncrypt(rk: rk, capsule: cap)

        var out = Data()
        out.append(encodeCapsule(reCap))
        out.append(pubX.uncompressed65)
        return out
    }

    public static func newDecryptor(receiverPrivateKeyHex: String, reCapsule: Data) throws -> Decryptor {
        if reCapsule.count != 250 {
            throw DIDEncryptError.invalidLength(expected: 250, actual: reCapsule.count)
        }
        let priv = try Secp256k1PrivateKey(raw32: try receiverPrivateKeyHex.didEncryptHexData().normalizedPrivateKeyBytes())

        let cap = try decodeCapsule(Data(reCapsule.prefix(185)))
        let pubX = try Secp256k1PublicKey(uncompressed65: Data(reCapsule.suffix(65)))

        let keyBytes = try decryptAESKey(receiverPriv: priv, capsule: cap, pubX: pubX)
        return Decryptor(aesKey32: Data(keyBytes.prefix(32)), baseNonce12: Data(keyBytes.prefix(12)), chunkSize: cap.chunkSize)
    }

    public static func newDecryptorByOwner(ownerPrivateKeyHex: String, capsule: Data) throws -> Decryptor {
        if capsule.count != 185 {
            throw DIDEncryptError.invalidLength(expected: 185, actual: capsule.count)
        }
        let priv = try Secp256k1PrivateKey(raw32: try ownerPrivateKeyHex.didEncryptHexData().normalizedPrivateKeyBytes())
        let cap = try decodeCapsule(capsule)

        let keyBytes = try decryptAESKeyByOwner(ownerPriv: priv, capsule: cap)
        return Decryptor(aesKey32: Data(keyBytes.prefix(32)), baseNonce12: Data(keyBytes.prefix(12)), chunkSize: cap.chunkSize)
    }
}

private extension Data {
    func normalizedPrivateKeyBytes() throws -> Data {
        if count == 32 { return self }
        if count > 32 { throw DIDEncryptError.invalidLength(expected: 32, actual: count) }
        return Data(repeating: 0, count: 32 - count) + self
    }
}
