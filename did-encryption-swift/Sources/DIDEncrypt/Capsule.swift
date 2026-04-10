import Foundation
import BigInt

let didEncryptMaxChunkSize: UInt32 = 16 * 1024 * 1024

struct Capsule: Equatable {
    let E: Secp256k1PublicKey
    let V: Secp256k1PublicKey
    let S: BigUInt
    let chunkSize: UInt32
    let version: UInt8
}

func encodeCapsule(_ cap: Capsule) -> Data {
    let eBytes = cap.E.uncompressed65
    let vBytes = cap.V.uncompressed65
    let eX = eBytes.subdata(in: 1..<33)
    let eY = eBytes.subdata(in: 33..<65)
    let vX = vBytes.subdata(in: 1..<33)
    let vY = vBytes.subdata(in: 33..<65)

    var w = ByteWriter()
    w.writeUInt32LE(UInt32(eX.count)); w.write(eX)
    w.writeUInt32LE(UInt32(eY.count)); w.write(eY)
    w.writeUInt32LE(UInt32(vX.count)); w.write(vX)
    w.writeUInt32LE(UInt32(vY.count)); w.write(vY)

    let sBytes = cap.S.toBigEndian(minBytes: 32)
    w.writeUInt32LE(UInt32(sBytes.count)); w.write(sBytes)

    w.writeUInt32LE(cap.chunkSize)
    w.writeUInt8(cap.version)
    return w.data
}

func decodeCapsule(_ data: Data) throws -> Capsule {
    var r = ByteReader(data)

    let eXLen = Int(try r.readUInt32LE())
    guard eXLen == 32 else { throw DIDEncryptError.invalidCapsule }
    let eX = try r.readBytes(count: eXLen)
    let eYLen = Int(try r.readUInt32LE())
    guard eYLen == 32 else { throw DIDEncryptError.invalidCapsule }
    let eY = try r.readBytes(count: eYLen)

    let vXLen = Int(try r.readUInt32LE())
    guard vXLen == 32 else { throw DIDEncryptError.invalidCapsule }
    let vX = try r.readBytes(count: vXLen)
    let vYLen = Int(try r.readUInt32LE())
    guard vYLen == 32 else { throw DIDEncryptError.invalidCapsule }
    let vY = try r.readBytes(count: vYLen)

    let sLen = Int(try r.readUInt32LE())
    guard sLen == 32 else { throw DIDEncryptError.invalidCapsule }
    let sBytes = try r.readBytes(count: sLen)

    let chunkSize = try r.readUInt32LE()
    let version = try r.readUInt8()
    guard version == 0 else { throw DIDEncryptError.invalidCapsule }
    guard r.offset == data.count else { throw DIDEncryptError.invalidCapsule }
    guard chunkSize == 0 || chunkSize <= didEncryptMaxChunkSize else { throw DIDEncryptError.chunkSizeOutOfRange }

    func makePub(x: Data, y: Data) throws -> Secp256k1PublicKey {
        var d = Data([0x04])
        d.append(x)
        d.append(y)
        return try Secp256k1PublicKey(uncompressed65: d)
    }

    return Capsule(
        E: try makePub(x: eX, y: eY),
        V: try makePub(x: vX, y: vY),
        S: BigUInt.fromBigEndian(sBytes),
        chunkSize: chunkSize,
        version: version
    )
}
