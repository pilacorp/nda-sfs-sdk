import Foundation
import BigInt

enum Secp256k1Constants {
    static let n = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
}

extension BigUInt {
    static func fromBigEndian(_ data: Data) -> BigUInt {
        var res = BigUInt(0)
        for b in data {
            res = (res << 8) | BigUInt(b)
        }
        return res
    }

    func toBigEndian(minBytes: Int? = nil) -> Data {
        if self == 0 {
            let zeros = Data(repeating: 0, count: Swift.max(1, minBytes ?? 1))
            return zeros
        }

        var x = self
        var bytes: [UInt8] = []
        while x > 0 {
            bytes.append(UInt8((x & 0xff)))
            x >>= 8
        }
        bytes.reverse()

        if let minBytes, bytes.count < minBytes {
            return Data(repeating: 0, count: minBytes - bytes.count) + Data(bytes)
        }
        return Data(bytes)
    }
}

func modN(_ x: BigUInt) -> BigUInt { x % Secp256k1Constants.n }

func modNAdd(_ a: BigUInt, _ b: BigUInt) -> BigUInt { (a + b) % Secp256k1Constants.n }

func modNMul(_ a: BigUInt, _ b: BigUInt) -> BigUInt { (a * b) % Secp256k1Constants.n }

func modNInverse(_ a: BigUInt) throws -> BigUInt {
    // Extended Euclid over integers; assumes a != 0 and gcd(a, n) == 1.
    if a == 0 { throw DIDEncryptError.invalidPrivateKey }
    let modulus = Secp256k1Constants.n

    var t = BigInt(0)
    var newT = BigInt(1)
    var r = BigInt(modulus)
    var newR = BigInt(a)

    while newR != 0 {
        let q = r / newR
        (t, newT) = (newT, t - q * newT)
        (r, newR) = (newR, r - q * newR)
    }

    if r != 1 { throw DIDEncryptError.invalidPrivateKey }
    if t < 0 { t += BigInt(modulus) }

    guard let inv = BigUInt(exactly: t) else { throw DIDEncryptError.invalidPrivateKey }
    return inv
}
