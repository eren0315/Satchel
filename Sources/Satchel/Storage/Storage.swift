import Foundation

private func posixError(_ path: String? = nil) -> Error {
    var info: [String: Any] = [:]
    if let path { info[NSFilePathErrorKey] = path }
    return NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: info)
}

/// 파일 읽기 저장소 (`pread` — 여러 스레드에서 동시에 읽어도 안전).
public final class FileReadStorage: ArchiveReadable, @unchecked Sendable {
    private let fd: Int32
    private let length: UInt64

    /// `followsSymlinks == false` 면 `O_NOFOLLOW` 로 연다 — 확인한 뒤 링크로 바뀐 경로를 따라가지 않는다.
    public init(url: URL, followsSymlinks: Bool = true) throws {
        fd = open(url.path, O_RDONLY | O_CLOEXEC | (followsSymlinks ? 0 : O_NOFOLLOW))
        guard fd >= 0 else { throw posixError(url.path) }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            let e = posixError(url.path)
            close(fd)
            throw e
        }
        length = UInt64(st.st_size)
    }

    deinit { close(fd) }

    public func size() throws -> UInt64 { length }

    public func read(at offset: UInt64, count: Int) throws -> [UInt8] {
        guard count > 0 else { return [] }
        var buffer = [UInt8](repeating: 0, count: count)
        var done = 0
        while done < count {
            let n = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress! + done, count - done, off_t(offset) + off_t(done)) }
            if n < 0 {
                if errno == EINTR { continue }
                throw posixError()
            }
            if n == 0 { break }
            done += n
        }
        if done < count { buffer.removeLast(count - done) }
        return buffer
    }
}

/// 메모리 읽기 저장소. `Data` 를 복사하지 않고 그대로 들고 있는다.
public struct MemoryReadStorage: ArchiveReadable {
    let data: Data

    public init(data: Data) { self.data = data }
    public init(bytes: [UInt8]) { data = Data(bytes) }

    public func size() throws -> UInt64 { UInt64(data.count) }

    public func read(at offset: UInt64, count: Int) throws -> [UInt8] {
        guard offset < UInt64(data.count), count > 0 else { return [] }
        let start = data.startIndex + Int(offset)
        let end = min(data.endIndex, start + count)
        return [UInt8](data[start..<end])
    }
}

/// 파일 쓰기 저장소 — 같은 폴더의 임시 파일에 쓰고 `commit()` 에서 최종 경로로 옮긴다.
public final class FileWriteStorage: ArchiveWritable {
    private let destination: URL
    private let temporary: URL
    private var fd: Int32
    public private(set) var position: UInt64 = 0
    private var done = false

    /// `url` 에 이미 파일이 있으면 `ZipError.destinationExists`.
    public init(url: URL) throws {
        destination = url
        if FileManager.default.fileExists(atPath: url.path) { throw ZipError.destinationExists(url.path) }
        temporary = url.deletingLastPathComponent().appendingPathComponent(".satchel-\(UUID().uuidString).tmp")
        fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o644)
        guard fd >= 0 else { throw posixError(temporary.path) }
    }

    deinit { if !done { discard() } }

    public func write(_ bytes: [UInt8]) throws {
        try write(bytes, at: position)
        position += UInt64(bytes.count)
    }

    public func write(_ bytes: [UInt8], at offset: UInt64) throws {
        var written = 0
        while written < bytes.count {
            let n = bytes.withUnsafeBytes { pwrite(fd, $0.baseAddress! + written, bytes.count - written, off_t(offset) + off_t(written)) }
            if n < 0 {
                if errno == EINTR { continue }
                throw posixError(temporary.path)
            }
            written += n
        }
    }

    public func truncate(to offset: UInt64) throws {
        guard ftruncate(fd, off_t(offset)) == 0 else { throw posixError(temporary.path) }
        position = offset
    }

    public func commit() throws {
        guard !done else { return }
        guard fsync(fd) == 0 else { throw posixError(temporary.path) }
        close(fd)
        fd = -1
        guard renamex_np(temporary.path, destination.path, UInt32(RENAME_EXCL)) == 0 else {
            let exists = errno == EEXIST
            let e = posixError(destination.path)
            unlink(temporary.path)
            done = true
            if exists { throw ZipError.destinationExists(destination.path) }
            throw e
        }
        done = true
    }

    public func discard() {
        guard !done else { return }
        if fd >= 0 { close(fd) }
        fd = -1
        unlink(temporary.path)
        done = true
    }
}

/// 메모리 쓰기 저장소.
public final class MemoryWriteStorage: ArchiveWritable {
    public private(set) var bytes: [UInt8] = []
    public var position: UInt64 { UInt64(bytes.count) }
    public var data: Data { Data(bytes) }

    public init() {}

    public func write(_ b: [UInt8]) throws { bytes.append(contentsOf: b) }

    public func write(_ b: [UInt8], at offset: UInt64) throws {
        let start = Int(offset)
        let end = start + b.count
        if end > bytes.count { bytes.append(contentsOf: [UInt8](repeating: 0, count: end - bytes.count)) }
        bytes.replaceSubrange(start..<end, with: b)
    }

    public func truncate(to offset: UInt64) throws { bytes.removeLast(bytes.count - Int(offset)) }
    public func commit() throws {}
    public func discard() { bytes.removeAll() }
}
