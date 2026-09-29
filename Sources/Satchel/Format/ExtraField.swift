import Foundation

/// zip 헤더의 extra field 하나 (id + 데이터 그대로).
public struct ExtraField: Sendable, Hashable {
    public let id: UInt16
    public let data: [UInt8]

    public init(id: UInt16, data: [UInt8]) {
        self.id = id
        self.data = data
    }
}

enum ExtraFieldID {
    static let zip64: UInt16 = 0x0001
    static let extendedTimestamp: UInt16 = 0x5455
    static let unicodePath: UInt16 = 0x7075
    static let winZipAES: UInt16 = 0x9901
}

extension ExtraField {
    /// 관대한 해석 — 길이가 맞지 않는 꼬리(일부 도구의 패딩)는 버린다.
    static func parse(_ bytes: [UInt8]) -> [ExtraField] {
        var fields: [ExtraField] = []
        var r = ByteReader(bytes)
        while r.remaining >= 4 {
            guard let id = try? r.u16(), let size = try? r.u16(), let data = try? r.take(Int(size)) else { break }
            fields.append(ExtraField(id: id, data: data))
        }
        return fields
    }

    static func serialize(_ fields: [ExtraField]) -> [UInt8] {
        var w = ByteWriter()
        for f in fields {
            w.u16(f.id)
            w.u16(UInt16(f.data.count))
            w.append(f.data)
        }
        return w.bytes
    }

    // MARK: 0x5455 확장 시각 (수정 시각만)

    static func extendedTimestamp(_ date: Date) -> ExtraField {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        let clamped = Int32(clamping: Int64(max(min(seconds, Double(Int32.max)), Double(Int32.min))))
        var w = ByteWriter()
        w.u8(0x01)
        w.u32(UInt32(bitPattern: clamped))
        return ExtraField(id: ExtraFieldID.extendedTimestamp, data: w.bytes)
    }

    var extendedTimestampModificationDate: Date? {
        guard id == ExtraFieldID.extendedTimestamp, data.count >= 5, data[0] & 0x01 != 0 else { return nil }
        var r = ByteReader(data, offset: 1)
        guard let raw = try? r.u32() else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(Int32(bitPattern: raw)))
    }

    // MARK: 0x7075 유니코드 경로

    static func unicodePath(name: String, originalNameBytes: [UInt8]) -> ExtraField {
        var w = ByteWriter()
        w.u8(1)
        w.u32(CRC32.checksum(originalNameBytes))
        w.append(Array(name.utf8))
        return ExtraField(id: ExtraFieldID.unicodePath, data: w.bytes)
    }

    /// 원본 이름의 CRC 가 맞을 때만 UTF-8 이름을 돌려준다 (이름을 바꾸고 extra 를 안 고친 도구 대비).
    func unicodePathName(matching originalNameBytes: [UInt8]) -> String? {
        guard id == ExtraFieldID.unicodePath, data.count >= 5, data[0] == 1 else { return nil }
        var r = ByteReader(data, offset: 1)
        guard let crc = try? r.u32(), crc == CRC32.checksum(originalNameBytes) else { return nil }
        return String(bytes: data[5...], encoding: .utf8)
    }
}
