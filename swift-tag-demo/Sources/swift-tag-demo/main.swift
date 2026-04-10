import Foundation
import DIDEncrypt

do {
    let alice = try DIDEncrypt.generateKeys()
    let bob = try DIDEncrypt.generateKeys()

    let message = Data("swift-tag-demo".utf8)

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

    let decryptor = try DIDEncrypt.newDecryptor(
        receiverPrivateKeyHex: bob.privateKeyHex,
        reCapsule: reCapsule
    )

    let plaintext = try decryptor.decrypt(ciphertext)
    print(String(data: plaintext, encoding: .utf8) ?? "")
} catch {
    print("swift-tag-demo failed: \(error)")
    exit(1)
}
