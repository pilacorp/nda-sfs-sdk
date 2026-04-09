import Foundation

public struct Decryptor: Equatable {
    let aesKey32: Data
    let baseNonce12: Data
    let chunkSize: UInt32

    public func decrypt(_ ciphertext: Data) throws -> Data {
        if chunkSize > 0 { throw DIDEncryptError.streamModeNotAllowed }
        return try aesGcmDecrypt(ciphertextAndTag: ciphertext, key32: aesKey32, nonce12: baseNonce12)
    }

    public func decryptByOwner(_ ciphertext: Data) throws -> Data {
        try decrypt(ciphertext)
    }

    public func decryptStream(input: InputStream, output: OutputStream) throws {
        if chunkSize == 0 { throw DIDEncryptError.chunkSizeNotSet }

        let didOpenIn = (input.streamStatus == .notOpen)
        let didOpenOut = (output.streamStatus == .notOpen)
        if didOpenIn { input.open() }
        if didOpenOut { output.open() }
        defer {
            if didOpenIn { input.close() }
            if didOpenOut { output.close() }
        }

        let cs = Int(chunkSize)
        let overhead = 16
        let noncePrefix = baseNonce12.prefix(8)
        var idx: UInt32 = 0

        while true {
            let want = cs + overhead
            guard let chunk = try readUpTo(want, from: input) else { break }
            if chunk.count < overhead { throw DIDEncryptError.invalidCiphertext }

            var nonce = Data(noncePrefix)
            var be = idx.bigEndian
            withUnsafeBytes(of: &be) { nonce.append(contentsOf: $0) }
            idx &+= 1

            let pt = try aesGcmDecrypt(ciphertextAndTag: chunk, key32: aesKey32, nonce12: nonce)
            try writeAll(pt, to: output)

            if chunk.count < want { break }
        }
    }

    public func hex() -> String {
        var out = Data()
        out.append(aesKey32)
        out.append(baseNonce12)
        var cs = chunkSize.littleEndian
        withUnsafeBytes(of: &cs) { out.append(contentsOf: $0) }
        return out.didEncryptHexString
    }

    public static func fromHex(_ hex: String) throws -> Decryptor {
        let data = try hex.didEncryptHexData()
        let expected = 32 + 12 + 4
        guard data.count == expected else {
            throw DIDEncryptError.invalidLength(expected: expected, actual: data.count)
        }
        let aes = Data(data.prefix(32))
        let nonce = Data(data.subdata(in: 32..<44))
        let csData = data.suffix(4)
        let cs = csData.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian
        return Decryptor(aesKey32: aes, baseNonce12: nonce, chunkSize: cs)
    }
}
