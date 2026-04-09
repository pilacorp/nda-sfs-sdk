import Foundation

public struct Encryptor: Equatable {
    let aesKey32: Data
    let baseNonce12: Data
    let chunkSize: UInt32

    public func encrypt(_ data: Data) throws -> Data {
        if chunkSize > 0 { throw DIDEncryptError.streamModeNotAllowed }
        return try aesGcmEncrypt(plaintext: data, key32: aesKey32, nonce12: baseNonce12)
    }

    public func encryptStream(input: InputStream, output: OutputStream) throws {
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
        let noncePrefix = baseNonce12.prefix(8)
        var idx: UInt32 = 0

        while true {
            guard let chunk = try readUpTo(cs, from: input) else { break }

            var nonce = Data(noncePrefix)
            var be = idx.bigEndian
            withUnsafeBytes(of: &be) { nonce.append(contentsOf: $0) }
            idx &+= 1

            let ct = try aesGcmEncrypt(plaintext: chunk, key32: aesKey32, nonce12: nonce)
            try writeAll(ct, to: output)
        }
    }
}
