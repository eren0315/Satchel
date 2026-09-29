import Foundation

/// zip 쓰기. 순서대로 쓰는 객체라 한 스레드에서만 쓴다.
/// `finish()` 를 부르지 않고 해제되면 임시 파일을 지우고 결과를 만들지 않는다.
public final class ArchiveWriter {
    private let storage: any ArchiveWritable
    private let options: WriteOptions
    private let control: OperationControl
    private var records: [Record] = []
    private let tree = PathTree()
    private var finished = false

    public convenience init(url: URL, options: WriteOptions = .init()) throws {
        self.init(storage: try FileWriteStorage(url: url), options: options)
    }

    /// 메모리에 쓴다. 결과는 `finishData()`.
    public convenience init(options: WriteOptions = .init()) {
        self.init(storage: MemoryWriteStorage(), options: options)
    }

    public init(storage: any ArchiveWritable, options: WriteOptions = .init()) {
        self.storage = storage
        self.options = options
        control = OperationControl(progress: options.progress)
    }

    deinit { if !finished { storage.discard() } }

    // MARK: 항목 추가

    /// 파일 하나. `path` 가 nil 이면 파일 이름.
    public func addFile(at url: URL, as path: String? = nil, options entryOptions: EntryOptions? = nil) throws {
        let info = try FileInfo(url)
        guard info.type == .typeRegular else {
            if info.type == .typeSymbolicLink { throw ZipError.unsupported("symbolic link: \(url.lastPathComponent)") }
            throw ZipError.unsupported("not a regular file: \(url.lastPathComponent)")
        }
        try add(name: path ?? url.lastPathComponent, source: .file(url, info.size), isDirectory: false,
                date: info.modificationDate, permissions: info.permissions, entryOptions: entryOptions)
    }

    /// 폴더와 하위 전체. 항목 이름은 `path`(nil 이면 폴더 이름) 아래 상대 경로. 순서는 경로 순.
    public func addDirectory(at url: URL, as path: String? = nil, options entryOptions: EntryOptions? = nil) throws {
        let info = try FileInfo(url)
        guard info.type == .typeDirectory else { throw ZipError.unsupported("not a directory: \(url.lastPathComponent)") }
        let base = path ?? url.lastPathComponent
        try add(name: base, source: .empty, isDirectory: true, date: info.modificationDate,
                permissions: info.permissions, entryOptions: nil)

        let subpaths = try FileManager.default.subpathsOfDirectory(atPath: url.path).sorted()
        for sub in subpaths {
            if !options.includesHiddenFiles, sub.split(separator: "/").contains(where: { $0.hasPrefix(".") }) { continue }
            let child = url.appendingPathComponent(sub)
            let childInfo = try FileInfo(child)
            let name = base + "/" + sub
            switch childInfo.type {
            case .typeDirectory:
                try add(name: name, source: .empty, isDirectory: true, date: childInfo.modificationDate,
                        permissions: childInfo.permissions, entryOptions: nil)
            case .typeRegular:
                try add(name: name, source: .file(child, childInfo.size), isDirectory: false,
                        date: childInfo.modificationDate, permissions: childInfo.permissions, entryOptions: entryOptions)
            case .typeSymbolicLink:
                throw ZipError.unsupported("symbolic link: \(name)")
            default:
                throw ZipError.unsupported("not a regular file: \(name)")
            }
        }
    }

    /// 메모리의 데이터 하나.
    public func add(_ data: Data, as path: String, modificationDate: Date = Date(), options entryOptions: EntryOptions? = nil) throws {
        let bytes = [UInt8](data)
        try add(name: path, source: .bytes(bytes), isDirectory: false, date: modificationDate,
                permissions: nil, entryOptions: entryOptions)
    }

    /// 빈 폴더.
    public func addEmptyDirectory(as path: String, modificationDate: Date = Date()) throws {
        try add(name: path, source: .empty, isDirectory: true, date: modificationDate, permissions: nil, entryOptions: nil)
    }

    // MARK: 마무리

    /// 목차와 끝 레코드를 쓰고 확정한다.
    @discardableResult
    public func finish() throws -> CreateResult {
        guard !finished else { throw ZipError.unsupported("archive already finished") }
        let mode = options.zip64
        let cdStart = storage.position
        var usedZip64 = records.contains { $0.localZip64 }

        for r in records {
            var zip = ByteWriter()
            let bigU = r.localZip64 || r.uncompressedSize >= UInt64(ZipLimits.max32)
            let bigC = r.localZip64 || r.compressedSize >= UInt64(ZipLimits.max32)
            let bigO = mode == .always || r.localHeaderOffset >= UInt64(ZipLimits.max32)
            if bigU { zip.u64(r.uncompressedSize) }
            if bigC { zip.u64(r.compressedSize) }
            if bigO { zip.u64(r.localHeaderOffset) }
            let needsZip64 = bigU || bigC || bigO
            if needsZip64 && mode == .never { throw ZipError.unsupported("zip64 required but zip64 is .never") }
            usedZip64 = usedZip64 || needsZip64
            var extras = r.centralExtras
            if needsZip64 { extras.insert(ExtraField(id: ExtraFieldID.zip64, data: zip.bytes), at: 0) }
            let extraBytes = ExtraField.serialize(extras)

            var w = ByteWriter(capacity: 46 + r.name.count + extraBytes.count)
            w.u32(Signature.centralDirectoryHeader)
            w.u16(ZipLimits.versionMadeBy)
            w.u16(needsZip64 ? max(r.versionNeeded, 45) : r.versionNeeded)
            w.u16(r.flags)
            w.u16(r.methodID)
            w.u16(r.dosTime)
            w.u16(r.dosDate)
            w.u32(r.crc32)
            w.u32(bigC ? ZipLimits.max32 : UInt32(r.compressedSize))
            w.u32(bigU ? ZipLimits.max32 : UInt32(r.uncompressedSize))
            w.u16(UInt16(r.name.count))
            w.u16(UInt16(extraBytes.count))
            w.u16(0)   // 주석
            w.u16(0)   // 디스크
            w.u16(0)   // 내부 속성
            w.u32(r.externalAttributes)
            w.u32(bigO ? ZipLimits.max32 : UInt32(r.localHeaderOffset))
            w.append(r.name)
            w.append(extraBytes)
            try storage.write(w.bytes)
        }

        let cdSize = storage.position - cdStart
        let count = UInt64(records.count)
        let need64 = mode == .always || count >= UInt64(ZipLimits.max16)
            || cdSize >= UInt64(ZipLimits.max32) || cdStart >= UInt64(ZipLimits.max32)
        if need64 && mode == .never { throw ZipError.unsupported("zip64 required but zip64 is .never") }

        if need64 {
            usedZip64 = true
            let recordOffset = storage.position
            var z = ByteWriter()
            z.u32(Signature.zip64EndOfCentralDirectory)
            z.u64(44)
            z.u16(ZipLimits.versionMadeBy)
            z.u16(45)
            z.u32(0)
            z.u32(0)
            z.u64(count)
            z.u64(count)
            z.u64(cdSize)
            z.u64(cdStart)
            z.u32(Signature.zip64EndOfCentralDirectoryLocator)
            z.u32(0)
            z.u64(recordOffset)
            z.u32(1)
            try storage.write(z.bytes)
        }

        let commentBytes = Array((options.comment ?? "").utf8)
        guard commentBytes.count <= Int(ZipLimits.max16) else { throw ZipError.unsupported("comment longer than 65,535 bytes") }
        let all = mode == .always
        var e = ByteWriter()
        e.u32(Signature.endOfCentralDirectory)
        e.u16(0)
        e.u16(0)
        let count16 = (all || count >= UInt64(ZipLimits.max16)) ? ZipLimits.max16 : UInt16(count)
        e.u16(count16)
        e.u16(count16)
        e.u32((all || cdSize >= UInt64(ZipLimits.max32)) ? ZipLimits.max32 : UInt32(cdSize))
        e.u32((all || cdStart >= UInt64(ZipLimits.max32)) ? ZipLimits.max32 : UInt32(cdStart))
        e.u16(UInt16(commentBytes.count))
        e.append(commentBytes)
        try storage.write(e.bytes)

        try storage.commit()
        finished = true
        let entries = records.enumerated().map { Entry.make(header: $0.element.header, index: $0.offset, encoding: .automatic, registry: options.registry) }
        return CreateResult(entries: entries, usedZip64: usedZip64)
    }

    /// 메모리 저장소일 때 결과 바이트. 다른 저장소면 `finish()` 를 쓴다.
    public func finishData() throws -> Data {
        guard let memory = storage as? MemoryWriteStorage else {
            throw ZipError.unsupported("finishData() requires an in-memory writer")
        }
        try finish()
        return memory.data
    }

    // MARK: 내부

    private enum Source {
        case file(URL, UInt64)
        case bytes([UInt8])
        case empty

        var size: UInt64 {
            switch self {
            case .file(_, let s): return s
            case .bytes(let b): return UInt64(b.count)
            case .empty: return 0
            }
        }

        func forEachChunk(_ body: ([UInt8]) throws -> Void) throws {
            switch self {
            case .empty:
                return
            case .bytes(let b):
                var i = 0
                while i < b.count {
                    let end = min(b.count, i + ZipLimits.chunkSize)
                    try body(Array(b[i..<end]))
                    i = end
                }
            case .file(let url, _):
                let reader = try FileReadStorage(url: url, followsSymlinks: false)   // 확인 뒤 링크로 바뀌어도 따라가지 않는다
                var offset: UInt64 = 0
                while true {
                    let chunk = try reader.read(at: offset, count: ZipLimits.chunkSize)
                    if chunk.isEmpty { break }
                    try body(chunk)
                    offset += UInt64(chunk.count)
                }
            }
        }

        /// 압축률 미리보기용 앞부분.
        func prefix(_ count: Int) throws -> [UInt8] {
            switch self {
            case .empty: return []
            case .bytes(let b): return Array(b.prefix(count))
            case .file(let url, _): return try FileReadStorage(url: url, followsSymlinks: false).read(at: 0, count: count)
            }
        }

        func crc32() throws -> UInt32 {
            var crc = CRC32()
            try forEachChunk { crc.update($0) }
            return crc.value
        }
    }

    private struct Record {
        let name: [UInt8]
        let flags: UInt16
        let methodID: UInt16
        let versionNeeded: UInt16
        let dosTime: UInt16
        let dosDate: UInt16
        let crc32: UInt32
        let compressedSize: UInt64
        let uncompressedSize: UInt64
        let localHeaderOffset: UInt64
        let localZip64: Bool
        let centralExtras: [ExtraField]
        let externalAttributes: UInt32

        var header: EntryHeader {
            EntryHeader(versionMadeBy: ZipLimits.versionMadeBy, versionNeededToExtract: versionNeeded,
                        generalPurposeFlags: flags, compressionMethodID: methodID, dosTime: dosTime,
                        dosDate: dosDate, crc32: crc32, compressedSize: compressedSize,
                        uncompressedSize: uncompressedSize, rawName: name, extraFields: centralExtras,
                        rawComment: [], diskNumberStart: 0, internalAttributes: 0,
                        externalAttributes: externalAttributes, localHeaderOffset: localHeaderOffset,
                        usesZip64: localZip64)
        }
    }

    private struct FileInfo {
        let type: FileAttributeType
        let size: UInt64
        let modificationDate: Date
        let permissions: UInt16?

        init(_ url: URL) throws {
            let a = try FileManager.default.attributesOfItem(atPath: url.path)   // lstat
            type = (a[.type] as? FileAttributeType) ?? .typeUnknown
            size = (a[.size] as? NSNumber)?.uint64Value ?? 0
            modificationDate = (a[.modificationDate] as? Date) ?? Date()
            permissions = (a[.posixPermissions] as? NSNumber).map { UInt16(truncatingIfNeeded: $0.intValue) }
        }
    }

    private func add(name rawName: String, source: Source, isDirectory: Bool, date: Date,
                     permissions: UInt16?, entryOptions: EntryOptions?) throws {
        guard !finished else { throw ZipError.unsupported("archive already finished") }
        try control.check()

        // 이름: 경로 규칙 검사 → NFC → 폴더는 `/` 로 끝나게
        var components = try EntryPath.components(of: rawName)
        if options.normalizesFilenamesToNFC { components = components.map(\.precomposedStringWithCanonicalMapping) }
        let name = components.joined(separator: "/") + (isDirectory ? "/" : "")
        try tree.validate(components, isDirectory: isDirectory, path: name)

        let (nameBytes, utf8Flag, unicodeExtra) = try encodeName(name)
        guard nameBytes.count <= Int(ZipLimits.max16) else { throw ZipError.unsupported("name longer than 65,535 bytes") }

        let compression = isDirectory ? .store : (entryOptions?.compression ?? options.compression)
        let encryption = isDirectory ? .none : (entryOptions?.encryption ?? options.encryption)
        var codec = try resolveCodec(compression)
        let scheme = try resolveScheme(encryption)
        let store = options.registry.codec(for: StoreCodec.id)
        // 이미 압축된 데이터(사진·영상·zip)는 앞부분으로 미리 판정해 저장 방식으로 바로 쓴다 — 전체를 두 번 쓰지 않게.
        if codec.methodID == DeflateCodec.id, let store, !isDirectory, source.size >= UInt64(2 * ZipLimits.chunkSize),
           try Self.looksIncompressible(try source.prefix(ZipLimits.chunkSize), codec: codec) {
            codec = store
        }
        var passwordBytes: [UInt8] = []
        if scheme != nil {
            guard let password = entryOptions?.password ?? options.password else { throw ZipError.passwordRequired(entry: name) }
            guard let bytes = password.bytesForWriting, !bytes.isEmpty else {
                throw ZipError.unsupported("password is empty or not representable in its first encoding")
            }
            passwordBytes = bytes
        }

        let mode = (permissions.map { $0 & 0o7777 } ?? (isDirectory ? 0o755 : 0o644)) | (isDirectory ? 0o040000 : 0o100000)
        let external = UInt32(mode) << 16 | (isDirectory ? 0x10 : 0)
        let entry = EntryPlan(name: nameBytes, utf8Flag: utf8Flag, unicodeExtra: unicodeExtra, source: source,
                              isDirectory: isDirectory, date: date, externalAttributes: external)

        let start = storage.position
        let mark = control.completed
        control.addTotal(source.size)
        do {
            var record = try write(entry, codec: codec, scheme: scheme, password: passwordBytes, start: start)
            // 그래도 DEFLATE 결과가 원본보다 크거나 같으면 저장 방식으로 다시 쓴다 (안전망).
            if codec.methodID == DeflateCodec.id, let store, !isDirectory, record.payloadLength >= record.record.uncompressedSize {
                try storage.truncate(to: start)
                control.rollback(to: mark)
                record = try write(entry, codec: store, scheme: scheme, password: passwordBytes, start: start)
            }
            records.append(record.record)
        } catch {
            try? storage.truncate(to: start)
            control.rollback(to: mark)
            throw error
        }
        try tree.insert(components, isDirectory: isDirectory, path: name)
    }

    /// 앞부분을 압축해 봐서 97% 이상이면 압축이 안 되는 데이터로 본다.
    private static func looksIncompressible(_ sample: [UInt8], codec: any CompressionCodec) throws -> Bool {
        guard !sample.isEmpty else { return false }
        let probe = try codec.makeCompressor()
        let compressed = try probe.process(sample).count + probe.finish().count
        return compressed * 100 >= sample.count * 97
    }

    private struct EntryPlan {
        let name: [UInt8]
        let utf8Flag: Bool
        let unicodeExtra: ExtraField?
        let source: Source
        let isDirectory: Bool
        let date: Date
        let externalAttributes: UInt32
    }

    private func write(_ e: EntryPlan, codec: any CompressionCodec, scheme: (any EncryptionScheme)?,
                       password: [UInt8], start: UInt64) throws -> (record: Record, payloadLength: UInt64) {
        let (dosTime, dosDate) = DOSDateTime.encode(e.date)
        var preCRC: UInt32?
        if let scheme, scheme.requiresCRCBeforeEncryption { preCRC = try e.source.crc32() }
        let encryptor = try scheme?.makeEncryptor(password: password, context: EncryptionContext(
            compressionMethodID: codec.methodID, crc32: preCRC, dosModificationTime: dosTime,
            uncompressedSize: e.source.size))
        let adjustment = encryptor?.headerAdjustment

        let methodID = adjustment?.compressionMethodIDOverride ?? codec.methodID
        let flags = (e.utf8Flag ? GeneralPurposeFlag.utf8 : 0) | (adjustment?.generalPurposeFlags ?? 0)
        let reserveZip64 = options.zip64 == .always
            || (options.zip64 == .automatic && e.source.size >= ZipLimits.zip64ReserveThreshold)
        var versionNeeded = max(codec.versionNeededToExtract, e.isDirectory ? 20 : 10, adjustment?.versionNeededToExtract ?? 0)
        if reserveZip64 { versionNeeded = max(versionNeeded, 45) }

        var common: [ExtraField] = [ExtraField.extendedTimestamp(e.date)]
        if let u = e.unicodeExtra { common.append(u) }
        common += adjustment?.extraFields ?? []
        var localExtras = common
        if reserveZip64 { localExtras.insert(ExtraField(id: ExtraFieldID.zip64, data: [UInt8](repeating: 0, count: 16)), at: 0) }
        let localExtraBytes = ExtraField.serialize(localExtras)

        var h = ByteWriter(capacity: 30 + e.name.count + localExtraBytes.count)
        h.u32(Signature.localFileHeader)
        h.u16(versionNeeded)
        h.u16(flags)
        h.u16(methodID)
        h.u16(dosTime)
        h.u16(dosDate)
        h.u32(0)                                           // CRC — 나중에 보정
        h.u32(reserveZip64 ? ZipLimits.max32 : 0)          // 압축 크기
        h.u32(reserveZip64 ? ZipLimits.max32 : 0)          // 해제 크기
        h.u16(UInt16(e.name.count))
        h.u16(UInt16(localExtraBytes.count))
        h.append(e.name)
        h.append(localExtraBytes)
        try storage.write(h.bytes)
        let dataStart = storage.position

        var overhead: UInt64 = 0
        if let encryptor {
            let prefix = encryptor.prefix()
            overhead += UInt64(prefix.count)
            try storage.write(prefix)
        }
        let compressor = try codec.makeCompressor()
        var crc = CRC32()
        var consumed: UInt64 = 0
        func output(_ bytes: [UInt8]) throws {
            guard !bytes.isEmpty else { return }
            try storage.write(try encryptor?.process(bytes) ?? bytes)
        }
        try e.source.forEachChunk { chunk in
            try control.check()
            crc.update(chunk)
            consumed += UInt64(chunk.count)
            try output(try compressor.process(chunk))
            control.advance(chunk.count)
        }
        try output(try compressor.finish())
        if let encryptor {
            let tail = try encryptor.finish()
            if !tail.isEmpty { try storage.write(tail) }
            let trailer = try encryptor.trailer()
            overhead += UInt64(trailer.count)
            try storage.write(trailer)
        }
        let compressedSize = storage.position - dataStart

        if let preCRC, preCRC != crc.value {
            throw ZipError.corrupted(entry: String(decoding: e.name, as: UTF8.self), reason: "source changed while writing")
        }
        let needs64 = consumed >= UInt64(ZipLimits.max32) || compressedSize >= UInt64(ZipLimits.max32)
        if needs64 && !reserveZip64 {
            throw ZipError.unsupported(options.zip64 == .never
                ? "zip64 required but zip64 is .never"
                : "entry grew beyond 4 GiB without a reserved zip64 field")
        }

        let storedCRC = (adjustment?.storesCRC ?? true) ? crc.value : 0
        var patch = ByteWriter()
        patch.u32(storedCRC)
        if !reserveZip64 {
            patch.u32(UInt32(compressedSize))
            patch.u32(UInt32(consumed))
        }
        try storage.write(patch.bytes, at: start + 14)
        if reserveZip64 {
            var z = ByteWriter()
            z.u64(consumed)
            z.u64(compressedSize)
            try storage.write(z.bytes, at: start + 30 + UInt64(e.name.count) + 4)
        }

        let record = Record(name: e.name, flags: flags, methodID: methodID, versionNeeded: versionNeeded,
                            dosTime: dosTime, dosDate: dosDate, crc32: storedCRC, compressedSize: compressedSize,
                            uncompressedSize: consumed, localHeaderOffset: start, localZip64: reserveZip64,
                            centralExtras: common, externalAttributes: e.externalAttributes)
        return (record, compressedSize - overhead)
    }

    private func encodeName(_ name: String) throws -> (bytes: [UInt8], utf8Flag: Bool, unicodeExtra: ExtraField?) {
        guard let encoding = options.filenameEncoding.stringEncoding, encoding != .utf8 else {
            return (Array(name.utf8), true, nil)
        }
        guard let bytes = TextCodec.encode(name, encoding) else { throw ZipError.filenameEncodingFailed(name) }
        if TextCodec.isASCII(bytes) { return (bytes, false, nil) }
        return (bytes, false, ExtraField.unicodePath(name: name, originalNameBytes: bytes))
    }

    private func resolveCodec(_ method: CompressionMethod) throws -> any CompressionCodec {
        let id: UInt16
        switch method {
        case .store: id = StoreCodec.id
        case .deflate: id = DeflateCodec.id
        case .custom(let m): id = m
        }
        guard let codec = options.registry.codec(for: id) else { throw ZipError.unsupported("compression method \(id)") }
        return codec
    }

    /// 쓰기도 읽기와 같은 등록소를 거친다 — 등록소에서 뺀 방식은 쓰지 못하고, 교체한 구현이 쓰인다.
    private func resolveScheme(_ method: EncryptionMethod) throws -> (any EncryptionScheme)? {
        let id: EncryptionIdentifier
        switch method {
        case .none: return nil
        case .aes: id = .winZipAES
        case .custom(let custom): id = custom
        }
        guard let scheme = options.registry.scheme(for: id) else { throw ZipError.unsupported("encryption \(id.rawValue) is not registered") }
        // 내장 AES 는 강도를 호출마다 정한다. 교체한 구현은 자기 설정을 따른다.
        if case .aes(let strength) = method, scheme is WinZipAESScheme { return WinZipAESScheme(strength: strength) }
        return scheme
    }
}
