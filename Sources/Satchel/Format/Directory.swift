import Foundation

/// 목차(central directory) 전체.
struct ArchiveDirectory {
    let headers: [EntryHeader]
    let comment: [UInt8]
    /// 목차 시작 위치 — 모든 항목 데이터는 이 앞에 있어야 한다.
    let centralDirectoryOffset: UInt64

    static func read(from storage: any ArchiveReadable, maxEntryCount: Int) throws -> ArchiveDirectory {
        let size = try storage.size()
        guard size >= 22 else { throw ZipError.corrupted(entry: nil, reason: "not a zip file") }

        // 1. EOCD — 뒤에서부터 찾고, 주석 길이가 파일 끝과 정확히 맞아야 한다 (주석 안의 가짜 시그니처 방지).
        let tailLength = Int(min(size, 22 + 0xFFFF))
        let tailStart = size - UInt64(tailLength)
        let tail = try storage.read(at: tailStart, count: tailLength)
        guard tail.count == tailLength else { throw ZipError.corrupted(entry: nil, reason: "truncated file") }
        // 후보가 목차와 맞물리는지도 본다 — 목차 끝이 EOCD 바로 앞이거나, Zip64 locator 가 바로 앞에 있어야 한다.
        func consistent(_ i: Int) -> Bool {
            var c = ByteReader(tail, offset: i + 12)
            guard let size = try? c.u32(), let offset = try? c.u32() else { return false }
            let at = tailStart + UInt64(i)
            if UInt64(offset) + UInt64(size) == at { return true }
            if at >= 20, let loc = try? storage.read(at: at - 20, count: 4), loc == [0x50, 0x4b, 0x06, 0x07] { return true }
            return false
        }
        var eocdIndex: Int?
        var i = tail.count - 22
        while i >= 0 {
            if tail[i] == 0x50, tail[i + 1] == 0x4b, tail[i + 2] == 0x05, tail[i + 3] == 0x06 {
                let commentLength = Int(tail[i + 20]) | Int(tail[i + 21]) << 8
                if i + 22 + commentLength == tail.count, consistent(i) { eocdIndex = i; break }
            }
            i -= 1
        }
        guard let eocdIndex else { throw ZipError.corrupted(entry: nil, reason: "end of central directory not found") }
        let eocdOffset = tailStart + UInt64(eocdIndex)

        var r = ByteReader(tail, offset: eocdIndex + 4)
        let disk = try r.u16()
        let cdDisk = try r.u16()
        _ = try r.u16()
        var entryCount = UInt64(try r.u16())
        var cdSize = UInt64(try r.u32())
        var cdOffset = UInt64(try r.u32())
        let commentLength = Int(try r.u16())
        let comment = try r.take(commentLength)
        var directoryEnd = eocdOffset

        // 2. Zip64 EOCD locator 가 바로 앞에 있으면 64비트 값을 쓴다.
        var zip64 = false
        if eocdOffset >= 20 {
            let loc = try storage.read(at: eocdOffset - 20, count: 20)
            var lr = ByteReader(loc)
            if loc.count == 20, try lr.u32() == Signature.zip64EndOfCentralDirectoryLocator {
                _ = try lr.u32()
                let recordOffset = try lr.u64()
                let totalDisks = try lr.u32()
                guard totalDisks <= 1 else { throw ZipError.unsupported("multi-disk archive") }
                // 파일에서 읽은 값에 덧셈을 하지 않는다 (조작된 값이면 오버플로 트랩).
                guard eocdOffset >= 20 + 56, recordOffset <= eocdOffset - 20 - 56 else {
                    throw ZipError.corrupted(entry: nil, reason: "invalid zip64 locator")
                }
                let rec = try storage.read(at: recordOffset, count: 56)
                var zr = ByteReader(rec)
                guard try zr.u32() == Signature.zip64EndOfCentralDirectory else {
                    throw ZipError.corrupted(entry: nil, reason: "zip64 end of central directory not found")
                }
                _ = try zr.u64()   // 레코드 크기
                _ = try zr.u16()   // made by
                _ = try zr.u16()   // needed
                let d = try zr.u32()
                let cd = try zr.u32()
                guard d == 0, cd == 0 else { throw ZipError.unsupported("multi-disk archive") }
                _ = try zr.u64()
                entryCount = try zr.u64()
                cdSize = try zr.u64()
                cdOffset = try zr.u64()
                directoryEnd = recordOffset
                zip64 = true
            }
        }
        if !zip64 {
            guard disk == 0, cdDisk == 0 else { throw ZipError.unsupported("multi-disk archive") }
            if cdSize == UInt64(ZipLimits.max32) || cdOffset == UInt64(ZipLimits.max32) {
                throw ZipError.corrupted(entry: nil, reason: "zip64 locator missing")
            }
        }

        guard entryCount <= UInt64(maxEntryCount) else {
            throw ZipError.limitExceeded("entry count \(entryCount) > \(maxEntryCount)")
        }
        guard cdOffset <= directoryEnd, cdSize <= directoryEnd - cdOffset else {
            throw ZipError.corrupted(entry: nil, reason: "central directory out of bounds")
        }
        guard cdSize <= UInt64(Int.max) else { throw ZipError.corrupted(entry: nil, reason: "central directory too large") }

        // 3. 목차
        let cd = try storage.read(at: cdOffset, count: Int(cdSize))
        guard cd.count == Int(cdSize) else { throw ZipError.corrupted(entry: nil, reason: "truncated central directory") }
        var cr = ByteReader(cd)
        var headers: [EntryHeader] = []
        headers.reserveCapacity(Int(entryCount))
        for _ in 0..<entryCount {
            headers.append(try parseCentralHeader(&cr))
        }
        return ArchiveDirectory(headers: headers, comment: comment, centralDirectoryOffset: cdOffset)
    }

    private static func parseCentralHeader(_ r: inout ByteReader) throws -> EntryHeader {
        guard try r.u32() == Signature.centralDirectoryHeader else {
            throw ZipError.corrupted(entry: nil, reason: "invalid central directory header")
        }
        let madeBy = try r.u16()
        let needed = try r.u16()
        let flags = try r.u16()
        let method = try r.u16()
        let time = try r.u16()
        let date = try r.u16()
        let crc = try r.u32()
        let csize32 = try r.u32()
        let usize32 = try r.u32()
        let nameLength = Int(try r.u16())
        let extraLength = Int(try r.u16())
        let commentLength = Int(try r.u16())
        let disk16 = try r.u16()
        let internalAttributes = try r.u16()
        let externalAttributes = try r.u32()
        let offset32 = try r.u32()
        let name = try r.take(nameLength)
        let extraBytes = try r.take(extraLength)
        let comment = try r.take(commentLength)
        let extras = ExtraField.parse(extraBytes)

        var usize = UInt64(usize32)
        var csize = UInt64(csize32)
        var offset = UInt64(offset32)
        var disk = UInt32(disk16)
        var usesZip64 = false
        let needsU = usize32 == ZipLimits.max32
        let needsC = csize32 == ZipLimits.max32
        let needsO = offset32 == ZipLimits.max32
        let needsD = disk16 == ZipLimits.max16
        if needsU || needsC || needsO || needsD {
            guard let z = extras.first(where: { $0.id == ExtraFieldID.zip64 }) else {
                throw ZipError.corrupted(entry: nil, reason: "zip64 extra field missing")
            }
            var zr = ByteReader(z.data)
            if needsU { usize = try zr.u64() }
            if needsC { csize = try zr.u64() }
            if needsO { offset = try zr.u64() }
            if needsD { disk = try zr.u32() }
            usesZip64 = true
        } else if extras.contains(where: { $0.id == ExtraFieldID.zip64 }) {
            usesZip64 = true
        }
        guard disk == 0 else { throw ZipError.unsupported("multi-disk archive") }

        return EntryHeader(
            versionMadeBy: madeBy, versionNeededToExtract: needed, generalPurposeFlags: flags,
            compressionMethodID: method, dosTime: time, dosDate: date, crc32: crc,
            compressedSize: csize, uncompressedSize: usize, rawName: name, extraFields: extras,
            rawComment: comment, diskNumberStart: disk, internalAttributes: internalAttributes,
            externalAttributes: externalAttributes, localHeaderOffset: offset, usesZip64: usesZip64)
    }
}

/// 로컬 헤더에서 데이터 시작 위치를 얻는다 (목차와 로컬의 extra 길이는 다를 수 있다).
struct LocalHeader {
    let dataOffset: UInt64
    let rawName: [UInt8]

    static func read(from storage: any ArchiveReadable, at offset: UInt64) throws -> LocalHeader {
        let fixed = try storage.read(at: offset, count: 30)
        guard fixed.count == 30 else { throw ZipError.corrupted(entry: nil, reason: "truncated local header") }
        var r = ByteReader(fixed)
        guard try r.u32() == Signature.localFileHeader else {
            throw ZipError.corrupted(entry: nil, reason: "invalid local header")
        }
        try r.skip(22)
        let nameLength = Int(try r.u16())
        let extraLength = Int(try r.u16())
        let name = try storage.read(at: offset + 30, count: nameLength)
        guard name.count == nameLength else { throw ZipError.corrupted(entry: nil, reason: "truncated local header") }
        return LocalHeader(dataOffset: offset + 30 + UInt64(nameLength) + UInt64(extraLength), rawName: name)
    }
}
