import Foundation
import CryptoKit
import CryptoSwift
import BigInt

func sha3_256(_ message: Data) -> Data {
    if #available(iOS 26.0, macOS 26.0, tvOS 26.0, watchOS 26.0, *) {
        return Data(SHA3_256.hash(data: message))
    }
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
