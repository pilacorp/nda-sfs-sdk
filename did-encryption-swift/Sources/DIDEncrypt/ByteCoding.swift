import Foundation

struct ByteWriter {
    private(set) var data = Data()

    mutating func writeUInt32LE(_ value: UInt32) {
        var v = value.littleEndian
        withUnsafeBytes(of: &v) { data.append(contentsOf: $0) }
    }

    mutating func writeUInt8(_ value: UInt8) {
        data.append(value)
    }

    mutating func write(_ bytes: Data) {
        data.append(bytes)
    }
}

struct ByteReader {
    let data: Data
    private(set) var offset: Int = 0

    init(_ data: Data) { self.data = data }

    mutating func readUInt32LE() throws -> UInt32 {
        let n = 4
        guard offset + n <= data.count else { throw DIDEncryptError.truncatedStream }
        let sub = data.subdata(in: offset..<(offset + n))
        offset += n
        return sub.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian
    }

    mutating func readUInt8() throws -> UInt8 {
        guard offset + 1 <= data.count else { throw DIDEncryptError.truncatedStream }
        let b = data[offset]
        offset += 1
        return b
    }

    mutating func readBytes(count: Int) throws -> Data {
        guard offset + count <= data.count else { throw DIDEncryptError.truncatedStream }
        let sub = data.subdata(in: offset..<(offset + count))
        offset += count
        return sub
    }
}

