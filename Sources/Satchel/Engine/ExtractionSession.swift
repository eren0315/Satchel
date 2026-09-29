import Foundation

/// 진행률 · 취소.
final class OperationControl {
    let progress: Progress?

    init(progress: Progress?) { self.progress = progress }

    func check() throws {
        if progress?.isCancelled == true || Task.isCancelled { throw ZipError.cancelled }
    }

    func addTotal(_ n: UInt64) {
        guard let progress else { return }
        progress.totalUnitCount += Int64(clamping: n)
    }

    func advance(_ n: Int) { progress?.completedUnitCount += Int64(n) }
    var completed: Int64 { progress?.completedUnitCount ?? 0 }
    func rollback(to value: Int64) { progress?.completedUnitCount = value }
}

protocol EntrySink: AnyObject {
    func reset() throws
    func write(_ bytes: [UInt8]) throws
}

final class FileSink: EntrySink {
    private var fd: Int32
    private let url: URL

    init(url: URL) throws {
        self.url = url
        fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0o644)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSFilePathErrorKey: url.path]) }
    }

    deinit { close() }

    func reset() throws {
        guard ftruncate(fd, 0) == 0, lseek(fd, 0, SEEK_SET) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSFilePathErrorKey: url.path])
        }
    }

    func write(_ bytes: [UInt8]) throws {
        var written = 0
        while written < bytes.count {
            let n = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress! + written, bytes.count - written) }
            if n < 0 {
                if errno == EINTR { continue }
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSFilePathErrorKey: url.path])
            }
            written += n
        }
    }

    func close() {
        if fd >= 0 { Darwin.close(fd) }
        fd = -1
    }
}

/// 메모리 해제용. `Data` 에 바로 쌓아 반환할 때 다시 복사하지 않는다.
final class MemorySink: EntrySink {
    private(set) var data = Data()

    init(capacity: Int = 0) { data.reserveCapacity(capacity) }

    func reset() throws { data.removeAll(keepingCapacity: true) }
    func write(_ b: [UInt8]) throws { data.append(contentsOf: b) }
}

final class NullSink: EntrySink {
    func reset() throws {}
    func write(_ bytes: [UInt8]) throws {}
}

/// 전체 해제 한 번. 사전 점검 → 임시 폴더에 풀기 → 검증 끝나면 옮기기. 실패하면 흔적을 남기지 않는다.
final class ExtractionSession {
    struct Planned {
        let entry: Entry
        let components: [String]
    }

    let reader: ArchiveReader
    let destination: URL
    let options: ExtractOptions
    let staging: URL
    let plan: [Planned]
    let control: OperationControl

    private var extracted: [Entry] = []
    private var skipped: [Entry] = []
    private var directories: [(URL, Entry)] = []
    private let fileManager = FileManager.default

    init(reader: ArchiveReader, destination: URL, options: ExtractOptions) throws {
        self.reader = reader
        self.destination = destination.standardizedFileURL
        self.options = options
        plan = try Self.preflight(reader, options: options)
        control = OperationControl(progress: options.progress)
        control.addTotal(plan.reduce(0) { $0 &+ $1.entry.uncompressedSize })

        let parent = self.destination.deletingLastPathComponent()
        try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
        staging = parent.appendingPathComponent(".satchel-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: false,
                                        attributes: [.posixPermissions: NSNumber(value: 0o755)])
    }

    // MARK: 사전 점검 — 아무것도 쓰기 전에 전부

    @discardableResult
    static func preflight(_ reader: ArchiveReader, options: ExtractOptions) throws -> [Planned] {
        var plan: [Planned] = []
        var total: UInt64 = 0
        let tree = PathTree()

        for (i, entry) in reader.entries.enumerated() {
            if entry.nameDecodingFailed { throw ZipError.filenameEncodingFailed(entry.path) }
            try checkStructure(reader, index: i)
            let components = try EntryPath.components(of: entry.path)
            if entry.kind == .symlink { throw ZipError.unsafeEntryPath(entry.path, reason: "symbolic link") }
            try checkSupport(reader, index: i, allowed: options.allowedEncryption)
            try checkRatio(reader.headers[i], entry: entry, limits: options.limits)

            let (sum, overflow) = total.addingReportingOverflow(entry.uncompressedSize)
            guard !overflow, sum <= options.limits.maxTotalUncompressedSize else {
                throw ZipError.limitExceeded("total uncompressed size > \(options.limits.maxTotalUncompressedSize)")
            }
            total = sum
            try tree.insert(components, isDirectory: entry.kind == .directory, path: entry.path)
            plan.append(Planned(entry: entry, components: components))
        }
        return plan
    }

    /// 항목 단위 API 의 점검 — 전체 해제와 같은 구조 · 지원 · 상한 규칙.
    static func checkSingle(_ reader: ArchiveReader, index i: Int, limits: ExtractLimits, allowed: Set<EncryptionIdentifier>?) throws {
        let entry = reader.entries[i]
        try checkStructure(reader, index: i)
        try checkSupport(reader, index: i, allowed: allowed)
        try checkRatio(reader.headers[i], entry: entry, limits: limits)
        guard entry.uncompressedSize <= limits.maxTotalUncompressedSize else {
            throw ZipError.limitExceeded("uncompressed size > \(limits.maxTotalUncompressedSize)")
        }
    }

    /// 로컬/목차 이름 불일치 · 데이터 영역 겹침 · 목차 침범 (열 때 계산해 둔 값).
    private static func checkStructure(_ reader: ArchiveReader, index i: Int) throws {
        let entry = reader.entries[i]
        guard reader.localNameMatches[i] else {
            throw ZipError.corrupted(entry: entry.path, reason: "local header name differs from central directory")
        }
        if let reason = reader.structuralProblems[i] { throw ZipError.corrupted(entry: entry.path, reason: reason) }
    }

    private static func checkSupport(_ reader: ArchiveReader, index i: Int, allowed: Set<EncryptionIdentifier>?) throws {
        let h = reader.headers[i]
        let entry = reader.entries[i]
        if h.generalPurposeFlags & GeneralPurposeFlag.strongEncryption != 0 {
            throw ZipError.unsupported("PKWARE strong encryption: \(entry.path)")
        }
        if h.generalPurposeFlags & GeneralPurposeFlag.centralDirectoryEncrypted != 0 {
            throw ZipError.unsupported("central directory encryption")
        }
        if h.isEncrypted {
            guard let scheme = reader.options.registry.scheme(matching: h) else {
                throw ZipError.unsupported("unknown encryption: \(entry.path)")
            }
            if let allowed, !allowed.contains(scheme.identifier) { throw ZipError.disallowedEncryption(scheme.identifier) }
        }
        if entry.kind == .file, reader.options.registry.codec(for: entry.compressionMethodID) == nil {
            throw ZipError.unsupported("compression method \(entry.compressionMethodID): \(entry.path)")
        }
    }

    private static func checkRatio(_ h: EntryHeader, entry: Entry, limits: ExtractLimits) throws {
        guard h.uncompressedSize > 0 else { return }
        guard h.compressedSize > 0 else {
            throw ZipError.corrupted(entry: entry.path, reason: "zero compressed size with non-empty content")
        }
        if h.uncompressedSize / h.compressedSize > limits.maxCompressionRatio {
            throw ZipError.limitExceeded("compression ratio of \(entry.path) > \(limits.maxCompressionRatio)")
        }
    }

    // MARK: 항목 풀기 (임시 폴더 안)

    func extract(_ p: Planned, passwords: [[UInt8]]) throws -> ArchiveReader.Outcome {
        try control.check()
        let target = try EntryPath.resolve(p.components, in: staging)
        if p.entry.kind == .directory {
            try fileManager.createDirectory(at: target, withIntermediateDirectories: true)
            directories.append((target, p.entry))
            extracted.append(p.entry)
            return .success
        }
        try fileManager.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        let sink = try FileSink(url: target)
        let outcome: ArchiveReader.Outcome
        do {
            outcome = try reader.decode(index: p.entry.index, passwords: passwords, sink: sink, control: control)
        } catch {
            sink.close()
            throw error
        }
        sink.close()
        guard outcome == .success else {
            try? fileManager.removeItem(at: target)
            return outcome
        }
        try applyAttributes(to: target, entry: p.entry, isDirectory: false)
        extracted.append(p.entry)
        return .success
    }

    func skip(_ p: Planned) {
        if let target = try? EntryPath.resolve(p.components, in: staging) { try? fileManager.removeItem(at: target) }
        skipped.append(p.entry)
        control.advance(Int(clamping: p.entry.uncompressedSize))
    }

    private func applyAttributes(to url: URL, entry: Entry, isDirectory: Bool) throws {
        var attributes: [FileAttributeKey: Any] = [:]
        if options.restoresPermissions, let permissions = entry.unixPermissions {
            // rwx 만 · group/other 쓰기 제거(외부 zip 이 world-writable 을 강요하지 못하게) ·
            // setuid · setgid · sticky 제거 · 소유자 접근은 보장한다.
            let mode = (permissions & 0o755) | (isDirectory ? 0o700 : 0o600)
            attributes[.posixPermissions] = NSNumber(value: mode)
        }
        if options.restoresModificationDate, let date = entry.modificationDate {
            attributes[.modificationDate] = date
        }
        if !attributes.isEmpty { try fileManager.setAttributes(attributes, ofItemAtPath: url.path) }
    }

    // MARK: 확정

    func finalize() throws -> ExtractResult {
        try control.check()
        // 폴더 속성은 안의 파일을 다 쓴 뒤, 깊은 곳부터.
        for (url, entry) in directories.sorted(by: { $0.0.path.count > $1.0.path.count }) {
            try applyAttributes(to: url, entry: entry, isDirectory: true)
        }

        if !exists(destination) {
            try fileManager.moveItem(at: staging, to: destination)
        } else {
            guard isDirectory(destination) else { throw ZipError.destinationExists(destination.path) }
            // 옮기기 전에 전부 검사한다 — 충돌이 있으면 아무것도 옮기지 않는다.
            var conflicts: [String] = []
            try collectConflicts(from: staging, into: destination, relative: "", conflicts: &conflicts)
            if !options.overwrite, let first = conflicts.first { throw ZipError.destinationExists(first) }
            try merge(from: staging, into: destination)
        }
        cleanup()
        return ExtractResult(extracted: extracted, skipped: skipped)
    }

    func cleanup() {
        if exists(staging) { try? fileManager.removeItem(at: staging) }
    }

    private func type(of url: URL) -> FileAttributeType? {
        (try? fileManager.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType   // lstat — 링크를 따라가지 않는다
    }

    private func exists(_ url: URL) -> Bool { type(of: url) != nil }
    private func isDirectory(_ url: URL) -> Bool { type(of: url) == .typeDirectory }

    private func collectConflicts(from source: URL, into target: URL, relative: String, conflicts: inout [String]) throws {
        for name in try fileManager.contentsOfDirectory(atPath: source.path) {
            let s = source.appendingPathComponent(name)
            let t = target.appendingPathComponent(name)
            let rel = relative.isEmpty ? name : relative + "/" + name
            guard let tType = type(of: t) else { continue }
            if tType == .typeSymbolicLink {
                throw ZipError.unsafeEntryPath(rel, reason: "destination contains a symbolic link")
            }
            let sourceIsDirectory = isDirectory(s)
            let targetIsDirectory = tType == .typeDirectory
            if sourceIsDirectory && targetIsDirectory {
                try collectConflicts(from: s, into: t, relative: rel, conflicts: &conflicts)
            } else if sourceIsDirectory != targetIsDirectory {
                // 파일 ↔ 폴더 — overwrite 여도 바꾸지 않는다 (사용자 폴더 트리를 통째로 지우지 않는다).
                throw ZipError.destinationExists(t.path)
            } else {
                conflicts.append(t.path)
            }
        }
    }

    /// 충돌 검사를 통과한 뒤에만 불린다. 파일 교체는 `rename(2)` — 기존 파일이 지워진 채 남는 순간이 없다.
    /// 여러 항목을 옮기는 도중 입출력 에러가 나면 일부만 옮겨질 수 있다 (각 파일은 옛 것 또는 새 것 — 최선의 노력).
    private func merge(from source: URL, into target: URL) throws {
        for name in try fileManager.contentsOfDirectory(atPath: source.path) {
            let s = source.appendingPathComponent(name)
            let t = target.appendingPathComponent(name)
            if !exists(t) {
                try fileManager.moveItem(at: s, to: t)
            } else if isDirectory(s) && isDirectory(t) {
                try merge(from: s, into: t)
            } else {
                guard rename(s.path, t.path) == 0 else {
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSFilePathErrorKey: t.path])
                }
            }
        }
    }
}
