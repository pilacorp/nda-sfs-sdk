import Foundation
import BigInt

func generateAESKey(ownerPub: Secp256k1PublicKey, chunkSize: UInt32) throws -> (Capsule, Data) {
    let priE = try Secp256k1PrivateKey.generate()
    let pubE = try Secp256k1PublicKey(uncompressed65: priE.publicKeyUncompressed())
    let priV = try Secp256k1PrivateKey.generate()
    let pubV = try Secp256k1PublicKey(uncompressed65: priV.publicKeyUncompressed())

    let h = hashToCurveScalar(concat(pubE.uncompressed65, pubV.uncompressed65))

    let priEInt = BigUInt.fromBigEndian(priE.raw32)
    let priVInt = BigUInt.fromBigEndian(priV.raw32)

    let s = modNAdd(priVInt, modNMul(priEInt, h))
    let sum = modNAdd(priEInt, priVInt).toBigEndian(minBytes: 32)

    let point = try pointMul(ownerPub, scalar32: sum)
    let keyBytes = sha3_256(point.uncompressed65)

    let cap = Capsule(E: pubE, V: pubV, S: s, chunkSize: chunkSize, version: 0)
    return (cap, keyBytes)
}

func decryptAESKeyByOwner(ownerPriv: Secp256k1PrivateKey, capsule: Capsule) throws -> Data {
    let ePlusV = try pointAdd(capsule.E, capsule.V)
    let ownerPrivInt = BigUInt.fromBigEndian(ownerPriv.raw32)
    let scalar = ownerPrivInt.toBigEndian(minBytes: 32)
    let point = try pointMul(ePlusV, scalar32: scalar)
    return sha3_256(point.uncompressed65)
}

func rekeyGenerate(ownerPriv: Secp256k1PrivateKey, receiverPub: Secp256k1PublicKey) throws -> (rk: BigUInt, pubX: Secp256k1PublicKey) {
    let priX = try Secp256k1PrivateKey.generate()
    let pubX = try Secp256k1PublicKey(uncompressed65: priX.publicKeyUncompressed())

    let point = try pointMul(receiverPub, scalar32: priX.raw32)
    let d = hashToCurveScalar(concat(concat(pubX.uncompressed65, receiverPub.uncompressed65), point.uncompressed65))

    let ownerPrivInt = BigUInt.fromBigEndian(ownerPriv.raw32)
    let invD = try modNInverse(d)
    let rk = modNMul(ownerPrivInt, invD)

    return (rk, pubX)
}

func reEncrypt(rk: BigUInt, capsule: Capsule) throws -> Capsule {
    let h = hashToCurveScalar(concat(capsule.E.uncompressed65, capsule.V.uncompressed65))
    let temp = try pointMul(capsule.E, scalar32: h.toBigEndian(minBytes: 32))
    let x2 = try pointAdd(capsule.V, temp)

    let x1 = try baseMul(capsule.S.toBigEndian(minBytes: 32))

    guard x1.uncompressed65 == x2.uncompressed65 else { throw DIDEncryptError.capsuleMismatch }

    let rk32 = rk.toBigEndian(minBytes: 32)
    return Capsule(
        E: try pointMul(capsule.E, scalar32: rk32),
        V: try pointMul(capsule.V, scalar32: rk32),
        S: capsule.S,
        chunkSize: capsule.chunkSize,
        version: capsule.version
    )
}

func decryptAESKey(receiverPriv: Secp256k1PrivateKey, capsule: Capsule, pubX: Secp256k1PublicKey) throws -> Data {
    let S = try pointMul(pubX, scalar32: receiverPriv.raw32)
    let receiverPub = try Secp256k1PublicKey(uncompressed65: receiverPriv.publicKeyUncompressed())

    let d = hashToCurveScalar(
        concat(
            concat(pubX.uncompressed65, receiverPub.uncompressed65),
            S.uncompressed65
        )
    )

    let ePlusV = try pointAdd(capsule.E, capsule.V)
    let point = try pointMul(ePlusV, scalar32: d.toBigEndian(minBytes: 32))
    return sha3_256(point.uncompressed65)
}
