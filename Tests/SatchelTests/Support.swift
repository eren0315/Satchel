import Foundation
import XCTest
@testable import Satchel

// MARK: - 임시 폴더

final class TempDir {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("satchel-tests-\(UUID().uuidString)", isDirectory: true)
            .resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: url) }

    func path(_ p: String) -> URL { url.appendingPathComponent(p) }

    @discardableResult
    func write(_ p: String, _ contents: String) throws -> URL {
        try write(p, Data(contents.utf8))
    }

    @discardableResult
    func write(_ p: String, _ data: Data) throws -> URL {
        let u = path(p)
        try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: u)
        return u
    }

    @discardableResult
    func mkdir(_ p: String) throws -> URL {
        let u = path(p)
        try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    /// 경로 → 내용(파일) / nil(폴더). 숨김 파일 포함.
    static func snapshot(_ root: URL) throws -> [String: Data?] {
        var result: [String: Data?] = [:]
        for sub in try FileManager.default.subpathsOfDirectory(atPath: root.path) {
            let u = root.appendingPathComponent(sub)
            var isDir: ObjCBool = false
            FileManager.default.fileExists(atPath: u.path, isDirectory: &isDir)
            let key = sub.precomposedStringWithCanonicalMapping
            result[key] = isDir.boolValue ? .some(nil) : .some(try Data(contentsOf: u))
        }
        return result
    }

    /// 같은 부모 폴더에 해제 임시 폴더(.satchel-*)가 남지 않았는지.
    func leftovers() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: url.path).filter { $0.hasPrefix(".satchel-") }
    }
}

// MARK: - 외부 도구

struct ToolResult {
    let status: Int32
    let stdout: Data
    let stderr: String
}

enum Tools {
    static func find(_ candidates: [String]) -> String? {
        candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static let zip = find(["/usr/bin/zip"])
    static let unzip = find(["/usr/bin/unzip"])
    static let bsdtar = find(["/usr/bin/bsdtar"])
    static let ditto = find(["/usr/bin/ditto"])
    static let python = find(["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"])
    static let sevenZip = find(["/opt/homebrew/bin/7zz", "/usr/local/bin/7zz"])

    @discardableResult
    static func run(_ tool: String?, _ args: [String], cwd: URL? = nil, file: StaticString = #filePath, line: UInt = #line) throws -> ToolResult {
        guard let tool else { throw XCTSkip("tool not installed") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        if let cwd { p.currentDirectoryURL = cwd }
        let out = Pipe()
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return ToolResult(status: p.terminationStatus, stdout: o, stderr: String(decoding: e, as: UTF8.self))
    }

    /// 성공해야 하는 실행.
    @discardableResult
    static func require(_ tool: String?, _ args: [String], cwd: URL? = nil, file: StaticString = #filePath, line: UInt = #line) throws -> ToolResult {
        let r = try run(tool, args, cwd: cwd)
        XCTAssertEqual(r.status, 0, "\(tool ?? "?") \(args.joined(separator: " ")) failed: \(r.stderr)", file: file, line: line)
        return r
    }

    static func sh(_ script: String, cwd: URL? = nil) throws -> ToolResult {
        try run("/bin/sh", ["-c", script], cwd: cwd)
    }

    static func python(_ script: String, cwd: URL? = nil) throws -> ToolResult {
        try run(python, ["-c", script], cwd: cwd)
    }
}

/// 바이트를 셸 printf 용 8진 이스케이프로 (인수로 원시 바이트를 넘기기 위해).
func printfOctal(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "\\%03o", $0) }.joined()
}

// MARK: - 원시 zip 빌더 (악성·특수 zip 제작용)

struct RawEntry {
    var name: [UInt8]
    var data: [UInt8] = []
    var localName: [UInt8]?
    var method: UInt16 = 0
    var flags: UInt16 = 0
    var crc: UInt32?
    var compressedSizeOverride: UInt32?
    var uncompressedSizeOverride: UInt32?
    var madeBy: UInt16 = (3 << 8) | 20
    var externalAttributes: UInt32 = UInt32(0o100644) << 16
    var extra: [ExtraField] = []
    var localOffsetOverride: UInt32?
    var diskStart: UInt16 = 0

    init(_ name: String, _ data: String = "") {
        self.name = Array(name.utf8)
        self.data = Array(data.utf8)
    }

    init(rawName: [UInt8], data: [UInt8] = []) {
        name = rawName
        self.data = data
    }
}

enum RawZip {
    static func build(_ entries: [RawEntry], comment: [UInt8] = [], eocdDisk: UInt16 = 0) -> [UInt8] {
        var out = ByteWriter()
        var central = ByteWriter()
        for e in entries {
            let offset = UInt32(out.bytes.count)
            let crc = e.crc ?? CRC32.checksum(e.data)
            let csize = e.compressedSizeOverride ?? UInt32(e.data.count)
            let usize = e.uncompressedSizeOverride ?? UInt32(e.data.count)
            let extra = ExtraField.serialize(e.extra)
            let lname = e.localName ?? e.name
            out.u32(0x0403_4b50); out.u16(20); out.u16(e.flags); out.u16(e.method)
            out.u16(0); out.u16(0x21); out.u32(crc); out.u32(csize); out.u32(usize)
            out.u16(UInt16(lname.count)); out.u16(UInt16(extra.count)); out.append(lname); out.append(extra)
            out.append(e.data)

            central.u32(0x0201_4b50); central.u16(e.madeBy); central.u16(20); central.u16(e.flags); central.u16(e.method)
            central.u16(0); central.u16(0x21); central.u32(crc); central.u32(csize); central.u32(usize)
            central.u16(UInt16(e.name.count)); central.u16(UInt16(extra.count)); central.u16(0)
            central.u16(e.diskStart); central.u16(0); central.u32(e.externalAttributes)
            central.u32(e.localOffsetOverride ?? offset)
            central.append(e.name); central.append(extra)
        }
        let cdOffset = UInt32(out.bytes.count)
        out.append(central.bytes)
        out.u32(0x0605_4b50); out.u16(eocdDisk); out.u16(0)
        out.u16(UInt16(entries.count)); out.u16(UInt16(entries.count))
        out.u32(UInt32(central.bytes.count)); out.u32(cdOffset)
        out.u16(UInt16(comment.count)); out.append(comment)
        return out.bytes
    }
}

// MARK: - 편의

extension XCTestCase {
    func assertZipError(_ expression: @autoclosure () throws -> Any, file: StaticString = #filePath, line: UInt = #line,
                        _ check: (ZipError) -> Bool) {
        do {
            _ = try expression()
            XCTFail("expected ZipError", file: file, line: line)
        } catch let e as ZipError {
            XCTAssertTrue(check(e), "unexpected \(e)", file: file, line: line)
        } catch {
            XCTFail("unexpected error \(error)", file: file, line: line)
        }
    }

    func randomBytes(_ n: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in UInt8.random(in: 0...255, using: &g) }
    }
}

/// 테스트용 트리: 텍스트 · 빈 파일 · 한글 이름 · 중첩 · 빈 폴더 · 압축 안 되는 데이터 · 64 KiB 경계.
func makeSampleTree(in dir: TempDir, root: String = "src") throws -> URL {
    let text = String(repeating: "The quick brown fox jumps over the lazy dog. 다람쥐 헌 쳇바퀴에 타고파.\n", count: 2_000)
    try dir.write("\(root)/hello.txt", "hello satchel\n")
    try dir.write("\(root)/empty.txt", "")
    try dir.write("\(root)/한글 폴더/문서.txt", text)
    try dir.write("\(root)/nested/deeper/file.md", "# title\n")
    try dir.write("\(root)/random.bin", Data((0..<70_000).map { _ in UInt8.random(in: 0...255) }))
    try dir.write("\(root)/boundary-65536.bin", Data(repeating: 7, count: 65_536))
    try dir.write("\(root)/boundary-65537.bin", Data(repeating: 9, count: 65_537))
    try dir.mkdir("\(root)/empty-dir")
    return dir.path(root)
}
