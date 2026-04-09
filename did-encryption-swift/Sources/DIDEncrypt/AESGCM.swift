import Foundation
import CryptoKit

func aesGcmEncrypt(plaintext: Data, key32: Data, nonce12: Data) throws -> Data {
    guard key32.count == 32 else { throw DIDEncryptError.invalidLength(expected: 32, actual: key32.count) }
    guard nonce12.count == 12 else { throw DIDEncryptError.invalidLength(expected: 12, actual: nonce12.count) }

    let key = SymmetricKey(data: key32)
    let nonce = try AES.GCM.Nonce(data: nonce12)
    let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: Data())

    var out = Data()
    out.reserveCapacity(sealed.ciphertext.count + sealed.tag.count)
    out.append(sealed.ciphertext)
    out.append(sealed.tag)
    return out
}

func aesGcmDecrypt(ciphertextAndTag: Data, key32: Data, nonce12: Data) throws -> Data {
    guard key32.count == 32 else { throw DIDEncryptError.invalidLength(expected: 32, actual: key32.count) }
    guard nonce12.count == 12 else { throw DIDEncryptError.invalidLength(expected: 12, actual: nonce12.count) }
    guard ciphertextAndTag.count >= 16 else { throw DIDEncryptError.invalidCiphertext }

    let key = SymmetricKey(data: key32)
    let nonce = try AES.GCM.Nonce(data: nonce12)

    let ct = Data(ciphertextAndTag.prefix(ciphertextAndTag.count - 16))
    let tag = Data(ciphertextAndTag.suffix(16))
    let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
    return try AES.GCM.open(box, using: key, authenticating: Data())
}
