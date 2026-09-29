import Foundation

/// zip 읽기. 열 때 목차를 한 번 읽는다. 여러 스레드에서 동시에 써도 안전하다.
public final class ArchiveReader: Sendable {
    let storage: any ArchiveReadable
    public let options: ReadOptions
    let headers: [EntryHeader]
    let dataOffsets: [UInt64]
    let localNameMatches: [Bool]
    /// 항목별 구조 문제 (데이터 영역 겹침 · 목차 침범). 목록은 보여 주되 풀지는 않는다.
    let structuralProblems: [Int: String]
    let centralDirectoryOffset: UInt64

    public let entries: [Entry]
    public let comment: String?
    public let rawComment: [UInt8]

    public convenience init(url: URL, options: ReadOptions = .init()) throws {
        try self.init(storage: FileReadStorage(url: url), options: options)
    }

    public convenience init(data: Data, options: ReadOptions = .init()) throws {
        try self.init(storage: MemoryReadStorage(data: data), options: options)
    }

    public init(storage: any ArchiveReadable, options: ReadOptions = .init()) throws {
        self.storage = storage
        self.options = options
        let dir = try ArchiveDirectory.read(from: storage, maxEntryCount: options.maxEntryCount)
        headers = dir.headers
        centralDirectoryOffset = dir.centralDirectoryOffset
        rawComment = dir.comment
        comment = dir.comment.isEmpty ? nil : (String(bytes: dir.comment, encoding: .utf8)
            ?? TextCodec.decode(dir.comment, TextCodec.cp949) ?? TextCodec.decode(dir.comment, TextCodec.cp437))

        var offsets: [UInt64] = []
        var matches: [Bool] = []
        offsets.reserveCapacity(headers.count)
        matches.reserveCapacity(headers.count)
        for h in headers {
            guard h.localHeaderOffset < dir.centralDirectoryOffset else {
                throw ZipError.corrupted(entry: nil, reason: "local header out of bounds")
            }
            let local = try LocalHeader.read(from: storage, at: h.localHeaderOffset)
            offsets.append(local.dataOffset)
            matches.append(local.rawName == h.rawName)
        }
        dataOffsets = offsets
        localNameMatches = matches
        structuralProblems = Self.findStructuralProblems(headers: headers, dataOffsets: offsets,
                                                         centralDirectoryOffset: dir.centralDirectoryOffset)
        entries = headers.enumerated().map {
            Entry.make(header: $0.element, index: $0.offset, encoding: options.filenameEncoding, registry: options.registry)
        }
    }

    /// 데이터 영역(로컬 헤더 시작 ~ 압축 데이터 끝)이 서로 겹치거나 목차를 침범하는 항목 (겹침 폭탄).
    private static func findStructuralProblems(headers: [EntryHeader], dataOffsets: [UInt64],
                                               centralDirectoryOffset: UInt64) -> [Int: String] {
        var problems: [Int: String] = [:]
        let ranges = headers.indices.map { i -> (start: UInt64, end: UInt64, overflow: Bool, i: Int) in
            let (end, overflow) = dataOffsets[i].addingReportingOverflow(headers[i].compressedSize)
            return (headers[i].localHeaderOffset, end, overflow, i)
        }.sorted { $0.start < $1.start }
        for (k, r) in ranges.enumerated() {
            if r.overflow || r.end > centralDirectoryOffset {
                problems[r.i] = "data out of bounds"
            }
            if k + 1 < ranges.count, r.end > ranges[k + 1].start {
                problems[r.i] = "overlapping entries"
                problems[ranges[k + 1].i] = "overlapping entries"
            }
        }
        return problems
    }

    // MARK: 전체 해제

    /// 고정 비밀번호(또는 없음)로 전부 푼다. 전부 성공해야 결과가 나타난다.
    @discardableResult
    public func extractAll(to destination: URL, options: ExtractOptions = .init()) throws -> ExtractResult {
        if options.password == nil, let first = entries.first(where: \.isEncrypted) {
            try ExtractionSession.preflight(self, options: options)
            throw ZipError.passwordRequired(entry: first.path)
        }
        let session = try ExtractionSession(reader: self, destination: destination, options: options)
        defer { session.cleanup() }
        let passwords = options.password?.candidates ?? []
        for planned in session.plan {
            switch try session.extract(planned, passwords: passwords) {
            case .success: break
            case .needsPassword: throw ZipError.passwordRequired(entry: planned.entry.path)
            case .wrongPassword: throw ZipError.wrongPassword(entry: planned.entry.path)
            }
        }
        return try session.finalize()
    }

    /// 비밀번호 제공자에게 항목마다 물어 가며 푼다. 맞은 비밀번호는 기억해 다음 항목에 먼저 시도한다.
    /// 항목 사이마다 양보(`Task.yield`)한다 — 항목 하나를 푸는 동안은 동기 작업이다.
    @discardableResult
    public func extractAll(to destination: URL, options: ExtractOptions = .init(),
                           passwordProvider: any PasswordProvider) async throws -> ExtractResult {
        let session = try ExtractionSession(reader: self, destination: destination, options: options)
        defer { session.cleanup() }
        var known: [[UInt8]] = options.password?.candidates ?? []
        for planned in session.plan {
            await Task.yield()
            try session.control.check()
            var outcome = try session.extract(planned, passwords: planned.entry.isEncrypted ? known : [])
            var attempt = 0
            asking: while outcome != .success {
                attempt += 1
                let request = PasswordRequest(entry: planned.entry, attempt: attempt,
                                              reason: attempt == 1 ? .required : .wrongPassword)
                let tries: [[UInt8]]
                switch await passwordProvider.password(for: request) {
                case .password(let p): tries = p.candidates
                case .passwords(let ps): tries = ps.flatMap(\.candidates)
                case .skipEntry:
                    session.skip(planned)
                    break asking
                case .cancel:
                    throw ZipError.cancelled
                }
                try session.control.check()
                outcome = try session.extract(planned, passwords: tries)
                if outcome == .success {
                    known = tries + known.filter { !tries.contains($0) }
                }
            }
        }
        return try session.finalize()
    }

    // MARK: 항목 단위

    /// 항목 하나를 `url` 에 푼다. 검증이 끝나야 파일이 나타난다. `url` 에 이미 있으면 `destinationExists`.
    public func extract(_ entry: Entry, to url: URL, password: Password? = nil,
                        limits: ExtractLimits = .default,
                        allowedEncryption: Set<EncryptionIdentifier>? = nil) throws {
        let i = try index(of: entry)
        guard entry.kind == .file else {
            if entry.kind == .directory {
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
                return
            }
            throw ZipError.unsafeEntryPath(entry.path, reason: "symbolic link")
        }
        if FileManager.default.fileExists(atPath: url.path) { throw ZipError.destinationExists(url.path) }
        try ExtractionSession.checkSingle(self, index: i, limits: limits, allowed: allowedEncryption)
        let temp = url.deletingLastPathComponent().appendingPathComponent(".satchel-\(UUID().uuidString).tmp")
        let sink = try FileSink(url: temp)
        defer { sink.close(); try? FileManager.default.removeItem(at: temp) }
        let outcome = try decode(index: i, passwords: password?.candidates ?? [], sink: sink, control: OperationControl(progress: nil))
        try resolve(outcome, entry)
        sink.close()
        try FileManager.default.moveItem(at: temp, to: url)
    }

    /// 항목 하나를 메모리로 푼다. 검증이 끝나야 돌려준다.
    /// 기본 상한은 `ExtractLimits.inMemory` (512 MiB) — 수 MB 짜리 zip 으로 메모리를 고갈시키지 못하게.
    public func data(for entry: Entry, password: Password? = nil, limits: ExtractLimits = .inMemory,
                     allowedEncryption: Set<EncryptionIdentifier>? = nil) throws -> Data {
        let i = try index(of: entry)
        guard entry.kind == .file else { throw ZipError.unsupported("not a file: \(entry.path)") }
        try ExtractionSession.checkSingle(self, index: i, limits: limits, allowed: allowedEncryption)
        let sink = MemorySink(capacity: Int(min(entry.uncompressedSize, 64 << 20)))
        let outcome = try decode(index: i, passwords: password?.candidates ?? [], sink: sink, control: OperationControl(progress: nil))
        try resolve(outcome, entry)
        return sink.data
    }

    /// 풀지 않고 비밀번호가 맞는지 본다. `thorough` 면 무결성까지 검증한다(비용 = 해제, 쓰기 없음).
    public func verify(_ password: Password, for entry: Entry, thorough: Bool = false,
                       limits: ExtractLimits = .default) throws -> PasswordCheck {
        let i = try index(of: entry)
        let h = headers[i]
        guard h.isEncrypted else { return .correct }
        try ExtractionSession.checkSingle(self, index: i, limits: limits, allowed: nil)
        guard let scheme = options.registry.scheme(matching: h) else {
            throw ZipError.unsupported("encryption \(entry.encryption?.rawValue ?? "unknown")")
        }
        let prefix = try readPrefix(i, scheme)
        for candidate in password.candidates where !candidate.isEmpty {
            guard case .ready = try scheme.makeDecryptor(password: candidate, header: h, prefix: prefix) else { continue }
            guard thorough else { return .likelyCorrect }
            if try decode(index: i, passwords: [candidate], sink: NullSink(), control: OperationControl(progress: nil)) == .success {
                return .correct
            }
        }
        return .wrong
    }

    // MARK: 내부

    enum Outcome: Equatable { case success, needsPassword, wrongPassword }

    /// 해제기에 한 번에 넣는 입력 크기 — 선언 크기 검사 전에 조각 하나가 부풀 수 있는 양을 제한한다.
    private static let decompressorFeed = 8 * 1024

    private func index(of entry: Entry) throws -> Int {
        guard entry.index >= 0, entry.index < entries.count, entries[entry.index] == entry else {
            throw ZipError.unsupported("entry does not belong to this archive")
        }
        return entry.index
    }

    private func resolve(_ outcome: Outcome, _ entry: Entry) throws {
        switch outcome {
        case .success: return
        case .needsPassword: throw ZipError.passwordRequired(entry: entry.path)
        case .wrongPassword: throw ZipError.wrongPassword(entry: entry.path)
        }
    }

    private func readPrefix(_ i: Int, _ scheme: any EncryptionScheme) throws -> [UInt8] {
        let h = headers[i]
        let length = scheme.prefixLength(for: h)
        guard UInt64(length + scheme.trailerLength(for: h)) <= h.compressedSize else {
            throw ZipError.corrupted(entry: entries[i].path, reason: "encrypted data too short")
        }
        let prefix = try storage.read(at: dataOffsets[i], count: length)
        guard prefix.count == length else { throw ZipError.corrupted(entry: entries[i].path, reason: "truncated data") }
        return prefix
    }

    /// 항목 하나를 풀어 sink 에 쓴다. 비밀번호 후보를 차례로 시도한다 (빈 후보는 틀린 것으로 본다).
    func decode(index i: Int, passwords: [[UInt8]], sink: any EntrySink, control: OperationControl) throws -> Outcome {
        let h = headers[i]
        let name = entries[i].path
        let start = dataOffsets[i]
        guard start <= centralDirectoryOffset, h.compressedSize <= centralDirectoryOffset - start else {
            throw ZipError.corrupted(entry: name, reason: "data out of bounds")
        }
        let methodID = entries[i].compressionMethodID
        guard let codec = options.registry.codec(for: methodID) else {
            throw ZipError.unsupported("compression method \(methodID)")
        }

        guard h.isEncrypted else {
            try sink.reset()
            try pump(i, codec: codec, from: start, length: h.compressedSize, decryptor: nil, trailer: [], sink: sink, control: control)
            return .success
        }
        guard let scheme = options.registry.scheme(matching: h) else {
            throw ZipError.unsupported("encryption \(entries[i].encryption?.rawValue ?? "unknown")")
        }
        guard !passwords.isEmpty else { return .needsPassword }

        let prefix = try readPrefix(i, scheme)
        let trailerLength = scheme.trailerLength(for: h)
        let bodyStart = start + UInt64(prefix.count)
        let bodyLength = h.compressedSize - UInt64(prefix.count + trailerLength)
        let trailer = try storage.read(at: bodyStart + bodyLength, count: trailerLength)
        guard trailer.count == trailerLength else { throw ZipError.corrupted(entry: name, reason: "truncated data") }

        var integrityFailure: (wrongPassword: Bool, reason: String)?
        let mark = control.completed
        for candidate in passwords where !candidate.isEmpty {
            guard case .ready(let decryptor) = try scheme.makeDecryptor(password: candidate, header: h, prefix: prefix) else { continue }
            do {
                try sink.reset()
                try pump(i, codec: codec, from: bodyStart, length: bodyLength, decryptor: decryptor, trailer: trailer, sink: sink, control: control)
                return .success
            } catch ZipError.corrupted(entry: _, reason: let reason) {
                // 빠른 확인을 통과했지만 내용이 맞지 않는다 → 다음 후보.
                control.rollback(to: mark)
                integrityFailure = (decryptor.integrityFailureIndicatesWrongPassword, reason)
            }
        }
        if let f = integrityFailure, !f.wrongPassword {
            throw ZipError.corrupted(entry: name, reason: f.reason)
        }
        return .wrongPassword
    }

    private func pump(_ i: Int, codec: any CompressionCodec, from offset: UInt64, length: UInt64,
                      decryptor: (any EntryDecryptor)?, trailer: [UInt8], sink: any EntrySink,
                      control: OperationControl) throws {
        let h = headers[i]
        let name = entries[i].path
        let decompressor = try codec.makeDecompressor()
        var crc = CRC32()
        var produced: UInt64 = 0
        var fed = false

        func emit(_ plain: [UInt8]) throws {
            guard !plain.isEmpty else { return }
            produced += UInt64(plain.count)
            guard produced <= h.uncompressedSize else {
                throw ZipError.corrupted(entry: name, reason: "data exceeds declared size")
            }
            crc.update(plain)
            try sink.write(plain)
            control.advance(plain.count)
        }

        func feed(_ compressed: [UInt8]) throws {
            guard !compressed.isEmpty else { return }
            fed = true
            var k = 0
            while k < compressed.count {
                let end = min(compressed.count, k + Self.decompressorFeed)
                try emit(try decompressor.process(Array(compressed[k..<end])))
                k = end
            }
        }

        do {
            var position = offset
            var remaining = length
            while remaining > 0 {
                try control.check()
                let n = Int(min(remaining, UInt64(ZipLimits.chunkSize)))
                var chunk = try storage.read(at: position, count: n)
                guard chunk.count == n else { throw ZipError.corrupted(entry: name, reason: "truncated data") }
                position += UInt64(n)
                remaining -= UInt64(n)
                if let decryptor { chunk = try decryptor.process(chunk) }
                try feed(chunk)
            }
            if let decryptor {
                try feed(try decryptor.finish())
                try decryptor.verify(trailer: trailer)
            }
            // 데이터가 하나도 없는 빈 항목(압축 크기 0)은 방식과 관계없이 빈 내용이다.
            if fed { try emit(try decompressor.finish()) }
        } catch ZipError.corrupted(entry: nil, reason: let reason) {
            throw ZipError.corrupted(entry: name, reason: reason)
        }

        guard produced == h.uncompressedSize else {
            throw ZipError.corrupted(entry: name, reason: "size mismatch")
        }
        if !(decryptor?.providesIntegrity ?? false), crc.value != h.crc32 {
            throw ZipError.corrupted(entry: name, reason: "crc mismatch")
        }
    }
}
