import Foundation
import XCTest
@testable import Satchel

final class Zip64Tests: XCTestCase {

    func testAlwaysModeIsReadableEverywhere() throws {
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        var options = WriteOptions()
        options.zip64 = .always
        let result = try Zip.create(at: dir.path("out.zip"), from: [src], options: options)
        XCTAssertTrue(result.usedZip64)

        let reader = try ArchiveReader(url: dir.path("out.zip"))
        XCTAssertTrue(reader.entries.allSatisfy(\.isZip64))
        try Tools.require(Tools.unzip, ["-tq", "out.zip"], cwd: dir.url)
        let py = try Tools.python("import zipfile,sys; sys.exit(0 if zipfile.ZipFile('out.zip').testzip() is None else 1)", cwd: dir.url)
        XCTAssertEqual(py.status, 0, py.stderr)
        try dir.mkdir("b")
        try Tools.require(Tools.bsdtar, ["-xf", "../out.zip"], cwd: dir.path("b"))
        XCTAssertEqual(try TempDir.snapshot(src), try TempDir.snapshot(dir.path("b/src")))
    }

    func testReadPythonForcedZip64() throws {
        let dir = try TempDir()
        let script = """
        import zipfile
        with zipfile.ZipFile('z.zip', 'w', zipfile.ZIP_DEFLATED) as z:
            with z.open('big.txt', 'w', force_zip64=True) as f:
                f.write(b'zip64 ' * 20000)
            z.writestr('small.txt', 'small')
        """
        let r = try Tools.python(script, cwd: dir.url)
        XCTAssertEqual(r.status, 0, r.stderr)
        let reader = try ArchiveReader(url: dir.path("z.zip"))
        // 로컬 헤더에만 Zip64 extra 가 있고(크기가 작아) 목차에는 없다 — 데이터 위치 계산이 맞는지가 요점.
        XCTAssertEqual(try reader.data(for: reader.entries[0]), Data(String(repeating: "zip64 ", count: 20000).utf8))
        XCTAssertEqual(try reader.data(for: reader.entries[1]), Data("small".utf8))
    }

    func testReadInfoZipForcedZip64() throws {
        let dir = try TempDir()
        try dir.write("a.txt", String(repeating: "force ", count: 1000))
        let r = try Tools.sh("cat a.txt | \(Tools.zip ?? "zip") -q -fz - - > z.zip", cwd: dir.url)
        guard r.status == 0 else { throw XCTSkip("zip -fz unsupported: \(r.stderr)") }
        let reader = try ArchiveReader(url: dir.path("z.zip"))
        XCTAssertEqual(try reader.data(for: reader.entries[0]), try Data(contentsOf: dir.path("a.txt")))
    }

    func testMoreThan65535EntriesUsesZip64EndRecord() throws {
        let writer = ArchiveWriter()
        let count = 65_540
        for i in 0..<count { try writer.add(Data(), as: "f\(i)") }
        let data = try writer.finishData()
        let reader = try ArchiveReader(data: data)
        XCTAssertEqual(reader.entries.count, count)
        XCTAssertEqual(reader.entries.last?.path, "f\(count - 1)")

        let dir = try TempDir()
        try data.write(to: dir.path("many.zip"))
        let py = try Tools.python("import zipfile,sys; z=zipfile.ZipFile('many.zip'); sys.exit(0 if len(z.infolist())==\(count) else 1)", cwd: dir.url)
        XCTAssertEqual(py.status, 0, py.stderr)
    }

    func testNeverModeRefusesWhenRequired() throws {
        var options = WriteOptions()
        options.zip64 = .never
        let writer = ArchiveWriter(options: options)
        for i in 0..<65_535 { try writer.add(Data(), as: "f\(i)") }
        assertZipError(try writer.finishData()) { if case .unsupported = $0 { return true }; return false }
    }

    func testMaxEntryCountLimit() throws {
        let writer = ArchiveWriter()
        for i in 0..<20 { try writer.add(Data(), as: "f\(i)") }
        var options = ReadOptions()
        options.maxEntryCount = 10
        assertZipError(try ArchiveReader(data: try writer.finishData(), options: options)) {
            if case .limitExceeded = $0 { return true }; return false
        }
    }

    /// 4 GiB 초과 항목 왕복 — 오래 걸려서 `SATCHEL_LARGE_TESTS=1` 일 때만.
    func testLargerThan4GiBEntry() throws {
        guard ProcessInfo.processInfo.environment["SATCHEL_LARGE_TESTS"] == "1" else {
            throw XCTSkip("set SATCHEL_LARGE_TESTS=1")
        }
        let dir = try TempDir()
        let big = dir.path("big.bin")
        FileManager.default.createFile(atPath: big.path, contents: nil)
        let h = try FileHandle(forWritingTo: big)
        try h.truncate(atOffset: (1 << 32) + 1_000)   // 희소 파일
        try h.close()
        var options = WriteOptions()
        options.compression = .store
        let result = try Zip.create(at: dir.path("big.zip"), from: [big], options: options)
        XCTAssertTrue(result.usedZip64)
        let reader = try ArchiveReader(url: dir.path("big.zip"))
        XCTAssertEqual(reader.entries[0].uncompressedSize, (1 << 32) + 1_000)
        try Tools.require(Tools.unzip, ["-tq", "big.zip"], cwd: dir.url)
    }
}
