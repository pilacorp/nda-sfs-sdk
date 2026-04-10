import Foundation
import Security
import libsecp256k1

final class Secp256k1: @unchecked Sendable {
    static let shared = Secp256k1()

    private let ctx: OpaquePointer

    private init() {
        ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
    }

    deinit {
        secp256k1_context_destroy(ctx)
    }

    func verifySeckey(_ seckey32: Data) -> Bool {
        guard seckey32.count == 32 else { return false }
        return seckey32.withUnsafeBytes { ptr in
            secp256k1_ec_seckey_verify(ctx, ptr.bindMemory(to: UInt8.self).baseAddress!) == 1
        }
    }

    func createPubkey(seckey32: Data) throws -> secp256k1_pubkey {
        guard verifySeckey(seckey32) else { throw DIDEncryptError.invalidPrivateKey }
        var pub = secp256k1_pubkey()
        let ok = seckey32.withUnsafeBytes { ptr in
            secp256k1_ec_pubkey_create(ctx, &pub, ptr.bindMemory(to: UInt8.self).baseAddress!) == 1
        }
        guard ok else { throw DIDEncryptError.invalidPublicKey }
        return pub
    }

    func parsePubkey(_ serialized: Data) throws -> secp256k1_pubkey {
        var pub = secp256k1_pubkey()
        let ok = serialized.withUnsafeBytes { ptr in
            secp256k1_ec_pubkey_parse(ctx, &pub, ptr.bindMemory(to: UInt8.self).baseAddress!, serialized.count) == 1
        }
        guard ok else { throw DIDEncryptError.invalidPublicKey }
        return pub
    }

    func serializePubkey(_ pub: secp256k1_pubkey, compressed: Bool) throws -> Data {
        var outLen = compressed ? 33 : 65
        var out = Data(repeating: 0, count: outLen)
        var pubCopy = pub
        let flags = compressed ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)

        let ok = out.withUnsafeMutableBytes { outPtr in
            secp256k1_ec_pubkey_serialize(
                ctx,
                outPtr.bindMemory(to: UInt8.self).baseAddress!,
                &outLen,
                &pubCopy,
                flags
            ) == 1
        }
        guard ok else { throw DIDEncryptError.invalidPublicKey }
        if out.count != outLen { out = out.prefix(outLen) }
        return out
    }

    func pubkeyCombine(_ a: secp256k1_pubkey, _ b: secp256k1_pubkey) throws -> secp256k1_pubkey {
        var out = secp256k1_pubkey()
        var aa = a
        var bb = b

        return try withUnsafePointer(to: &aa) { p1 in
            try withUnsafePointer(to: &bb) { p2 in
                let ptrs: [UnsafePointer<secp256k1_pubkey>?] = [p1, p2]
                let ok = ptrs.withUnsafeBufferPointer { ptrBuf -> Bool in
                    secp256k1_ec_pubkey_combine(ctx, &out, ptrBuf.baseAddress!, ptrBuf.count) == 1
                }
                guard ok else { throw DIDEncryptError.invalidPublicKey }
                return out
            }
        }
    }

    func pubkeyTweakMul(_ pub: secp256k1_pubkey, tweak32: Data) throws -> secp256k1_pubkey {
        guard tweak32.count == 32 else { throw DIDEncryptError.invalidLength(expected: 32, actual: tweak32.count) }
        var out = pub
        let ok = tweak32.withUnsafeBytes { ptr in
            secp256k1_ec_pubkey_tweak_mul(ctx, &out, ptr.bindMemory(to: UInt8.self).baseAddress!) == 1
        }
        guard ok else { throw DIDEncryptError.invalidPublicKey }
        return out
    }
}

struct Secp256k1PrivateKey: Equatable {
    let raw32: Data

    init(raw32: Data) throws {
        guard raw32.count == 32 else { throw DIDEncryptError.invalidLength(expected: 32, actual: raw32.count) }
        guard Secp256k1.shared.verifySeckey(raw32) else { throw DIDEncryptError.invalidPrivateKey }
        self.raw32 = raw32
    }

    static func generate() throws -> Secp256k1PrivateKey {
        while true {
            var bytes = Data(repeating: 0, count: 32)
            let status = bytes.withUnsafeMutableBytes { ptr in
                SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
            }
            guard status == errSecSuccess else { continue }
            if Secp256k1.shared.verifySeckey(bytes) {
                return try Secp256k1PrivateKey(raw32: bytes)
            }
        }
    }

    func publicKeyUncompressed() throws -> Data {
        let pub = try Secp256k1.shared.createPubkey(seckey32: raw32)
        return try Secp256k1.shared.serializePubkey(pub, compressed: false)
    }
}

struct Secp256k1PublicKey: Equatable {
    // Stored as uncompressed bytes: 0x04 || X(32) || Y(32)
    let uncompressed65: Data

    init(uncompressed65: Data) throws {
        guard uncompressed65.count == 65 else { throw DIDEncryptError.invalidLength(expected: 65, actual: uncompressed65.count) }
        _ = try Secp256k1.shared.parsePubkey(uncompressed65)
        self.uncompressed65 = uncompressed65
    }

    static func fromCompressed(_ compressed33: Data) throws -> Secp256k1PublicKey {
        let pub = try Secp256k1.shared.parsePubkey(compressed33)
        return try Secp256k1PublicKey(uncompressed65: try Secp256k1.shared.serializePubkey(pub, compressed: false))
    }

    func compressed33() throws -> Data {
        let pub = try Secp256k1.shared.parsePubkey(uncompressed65)
        return try Secp256k1.shared.serializePubkey(pub, compressed: true)
    }
}

func pointAdd(_ a: Secp256k1PublicKey, _ b: Secp256k1PublicKey) throws -> Secp256k1PublicKey {
    let pa = try Secp256k1.shared.parsePubkey(a.uncompressed65)
    let pb = try Secp256k1.shared.parsePubkey(b.uncompressed65)
    let out = try Secp256k1.shared.pubkeyCombine(pa, pb)
    return try Secp256k1PublicKey(uncompressed65: try Secp256k1.shared.serializePubkey(out, compressed: false))
}

func pointMul(_ a: Secp256k1PublicKey, scalar32: Data) throws -> Secp256k1PublicKey {
    let pa = try Secp256k1.shared.parsePubkey(a.uncompressed65)
    let out = try Secp256k1.shared.pubkeyTweakMul(pa, tweak32: scalar32)
    return try Secp256k1PublicKey(uncompressed65: try Secp256k1.shared.serializePubkey(out, compressed: false))
}

func baseMul(_ scalar32: Data) throws -> Secp256k1PublicKey {
    let priv = try Secp256k1PrivateKey(raw32: scalar32)
    return try Secp256k1PublicKey(uncompressed65: priv.publicKeyUncompressed())
}
