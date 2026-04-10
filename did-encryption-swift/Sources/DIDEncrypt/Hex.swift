import Foundation

extension Data {
    var didEncryptHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

extension String {
    func didEncryptHexData() throws -> Data {
        let s = hasPrefix("0x") ? String(dropFirst(2)) : self
        guard s.count % 2 == 0 else { throw DIDEncryptError.invalidHex }
        var out = Data()
        out.reserveCapacity(s.count / 2)

        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let b = UInt8(s[i..<j], radix: 16) else { throw DIDEncryptError.invalidHex }
            out.append(b)
            i = j
        }
        return out
    }
}

