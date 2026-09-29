import Foundation

/// little-endian 바이트 읽기. 범위를 벗어나면 `ZipError.corrupted` 를 던진다.
struct ByteReader {
    let bytes: [UInt8]
    private(set) var offset: Int

    init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    var remaining: Int { bytes.count - offset }

    mutating func u8() throws -> UInt8 {
        try require(1)
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func u16() throws -> UInt16 {
        try require(2)
        defer { offset += 2 }
        return UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
    }

    mutating func u32() throws -> UInt32 {
        try require(4)
        defer { offset += 4 }
        var value: UInt32 = 0
        for i in 0..<4 { value |= UInt32(bytes[offset + i]) << (8 * UInt32(i)) }
        return value
    }

    mutating func u64() throws -> UInt64 {
        try require(8)
        defer { offset += 8 }
        var value: UInt64 = 0
        for i in 0..<8 { value |= UInt64(bytes[offset + i]) << (8 * UInt64(i)) }
        return value
    }

    mutating func take(_ count: Int) throws -> [UInt8] {
        try require(count)
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    mutating func skip(_ count: Int) throws {
        try require(count)
        offset += count
    }

    private func require(_ count: Int) throws {
        guard count >= 0, remaining >= count else {
            throw ZipError.corrupted(entry: nil, reason: "unexpected end of data")
        }
    }
}

/// little-endian 바이트 쓰기.
struct ByteWriter {
    private(set) var bytes: [UInt8] = []

    init(capacity: Int = 0) { bytes.reserveCapacity(capacity) }

    mutating func u8(_ v: UInt8) { bytes.append(v) }
    mutating func u16(_ v: UInt16) { for i in 0..<2 { bytes.append(UInt8(truncatingIfNeeded: v >> (8 * UInt16(i)))) } }
    mutating func u32(_ v: UInt32) { for i in 0..<4 { bytes.append(UInt8(truncatingIfNeeded: v >> (8 * UInt32(i)))) } }
    mutating func u64(_ v: UInt64) { for i in 0..<8 { bytes.append(UInt8(truncatingIfNeeded: v >> (8 * UInt64(i)))) } }
    mutating func append(_ b: [UInt8]) { bytes.append(contentsOf: b) }
}

enum Signature {
    static let localFileHeader: UInt32 = 0x0403_4b50
    static let centralDirectoryHeader: UInt32 = 0x0201_4b50
    static let endOfCentralDirectory: UInt32 = 0x0605_4b50
    static let zip64EndOfCentralDirectory: UInt32 = 0x0606_4b50
    static let zip64EndOfCentralDirectoryLocator: UInt32 = 0x0706_4b50
}

enum GeneralPurposeFlag {
    static let encrypted: UInt16 = 1 << 0
    static let dataDescriptor: UInt16 = 1 << 3
    static let strongEncryption: UInt16 = 1 << 6
    static let utf8: UInt16 = 1 << 11
    static let centralDirectoryEncrypted: UInt16 = 1 << 13
}

enum ZipLimits {
    static let max16: UInt16 = 0xFFFF
    static let max32: UInt32 = 0xFFFF_FFFF
    static let chunkSize = 64 * 1024
    /// 이 크기 이상이면 `.automatic` 모드에서 로컬 헤더에 Zip64 자리를 미리 잡는다 (DEFLATE 팽창 여유 포함).
    static let zip64ReserveThreshold: UInt64 = 0xFFFF_0000
    /// version made by = Unix(3) · 6.3
    static let versionMadeBy: UInt16 = (3 << 8) | 63
}

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}
