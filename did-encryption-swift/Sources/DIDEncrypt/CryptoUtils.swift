import Foundation
import CryptoSwift
import BigInt

func sha3_256(_ message: Data) -> Data {
    let digest = SHA3(variant: .sha256).calculate(for: Array(message))
    return Data(digest)
}

func concat(_ a: Data, _ b: Data) -> Data {
    var out = Data()
    out.reserveCapacity(a.count + b.count)
    out.append(a)
    out.append(b)
    return out
}

func hashToCurveScalar(_ hash: Data) -> BigUInt {
    modN(BigUInt.fromBigEndian(hash))
}
