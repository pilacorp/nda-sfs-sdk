import Foundation

func readUpTo(_ want: Int, from input: InputStream) throws -> Data? {
    if want <= 0 { return Data() }
    var buf = [UInt8](repeating: 0, count: want)
    var total = 0
    while total < want {
        let n = buf.withUnsafeMutableBytes { raw -> Int in
            let base = raw.bindMemory(to: UInt8.self).baseAddress!
            return input.read(base.advanced(by: total), maxLength: want - total)
        }
        if n < 0 { throw input.streamError ?? DIDEncryptError.truncatedStream }
        if n == 0 { break }
        total += n
    }
    if total == 0 { return nil }
    return Data(buf.prefix(total))
}

func writeAll(_ data: Data, to out: OutputStream) throws {
    var written = 0
    try data.withUnsafeBytes { ptr in
        guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return }
        while written < data.count {
            let n = out.write(base.advanced(by: written), maxLength: data.count - written)
            if n < 0 { throw out.streamError ?? DIDEncryptError.truncatedStream }
            written += n
        }
    }
}

