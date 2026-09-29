import Foundation
import XCTest
@testable import Satchel

/// 다른 도구가 만든 zip 을 풀고, Satchel 이 만든 zip 을 다른 도구로 검증한다.
final class CompatibilityTests: XCTestCase {

    private func assertSameTree(_ a: URL, _ b: URL, file: StaticString = #filePath, line: UInt = #line) throws {
        let sa = try TempDir.snapshot(a)
        let sb = try TempDir.snapshot(b)
        XCTAssertEqual(Set(sa.keys), Set(sb.keys), file: file, line: line)
        for (k, v) in sa { XCTAssertEqual(v, sb[k] ?? nil, "content differs: \(k)", file: file, line: line) }
    }

    // MARK: 해제 — 다른 도구 → Satchel

    func testExtractInfoZip() throws {
        let dir = try TempDir()
        _ = try makeSampleTree(in: dir)
        try Tools.require(Tools.zip, ["-q", "-r", "out.zip", "src"], cwd: dir.url)
        try Zip.extract(dir.path("out.zip"), to: dir.path("x"))
        try assertSameTree(dir.path("src"), dir.path("x/src"))
        XCTAssertEqual(try dir.leftovers(), [])
    }

    func testExtractInfoZipStreamedWithDataDescriptor() throws {
        let dir = try TempDir()
        try dir.write("a.txt", String(repeating: "stream me ", count: 5_000))
        // 표준 입력으로 받으면 크기를 몰라 data descriptor 를 쓴다.
        let r = try Tools.sh("cat a.txt | \(Tools.zip ?? "zip") -q - - > out.zip", cwd: dir.url)
        XCTAssertEqual(r.status, 0)
        let reader = try ArchiveReader(url: dir.path("out.zip"))
        XCTAssertEqual(reader.entries.count, 1)
        let data = try reader.data(for: reader.entries[0])
        XCTAssertEqual(data, try Data(contentsOf: dir.path("a.txt")))
    }

    func testExtractDitto() throws {
        let dir = try TempDir()
        _ = try makeSampleTree(in: dir)
        try Tools.require(Tools.ditto, ["-c", "-k", "--keepParent", "src", "out.zip"], cwd: dir.url)
        try Zip.extract(dir.path("out.zip"), to: dir.path("x"))
        try assertSameTree(dir.path("src"), dir.path("x/src"))
    }

    func testExtractPythonUnseekableStream() throws {
        let dir = try TempDir()
        let script = """
        import sys, zipfile
        with zipfile.ZipFile(sys.stdout.buffer, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('dir/', '')
            z.writestr('dir/한글.txt', '가나다' * 1000)
            z.writestr(zipfile.ZipInfo('stored.txt'), 'plain', compress_type=zipfile.ZIP_STORED)
        """
        let r = try Tools.python(script)
        XCTAssertEqual(r.status, 0, r.stderr)
        let reader = try ArchiveReader(data: r.stdout)
        XCTAssertEqual(reader.entries.map(\.path), ["dir/", "dir/한글.txt", "stored.txt"])
        XCTAssertEqual(String(decoding: try reader.data(for: reader.entries[1]), as: UTF8.self), String(repeating: "가나다", count: 1000))
        XCTAssertEqual(String(decoding: try reader.data(for: reader.entries[2]), as: UTF8.self), "plain")
    }

    func testExtractBsdtar() throws {
        let dir = try TempDir()
        _ = try makeSampleTree(in: dir)
        try Tools.require(Tools.bsdtar, ["--format", "zip", "-cf", "out.zip", "src"], cwd: dir.url)
        try Zip.extract(dir.path("out.zip"), to: dir.path("x"))
        try assertSameTree(dir.path("src"), dir.path("x/src"))
    }

    // MARK: 생성 — Satchel → 다른 도구

    func testCreatedArchivePassesUnzipAndPython() throws {
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        let result = try Zip.create(at: dir.path("out.zip"), from: [src])
        XCTAssertFalse(result.usedZip64)
        try Tools.require(Tools.unzip, ["-tq", "out.zip"], cwd: dir.url)
        let py = try Tools.python("import zipfile,sys; sys.exit(0 if zipfile.ZipFile('out.zip').testzip() is None else 1)", cwd: dir.url)
        XCTAssertEqual(py.status, 0, py.stderr)

        try dir.mkdir("u")
        try Tools.require(Tools.unzip, ["-q", "../out.zip"], cwd: dir.path("u"))
        try assertSameTree(src, dir.path("u/src"))
    }

    func testCreatedArchiveReadableByBsdtar() throws {
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        try Zip.create(at: dir.path("out.zip"), from: [src])
        try dir.mkdir("b")
        try Tools.require(Tools.bsdtar, ["-xf", "../out.zip"], cwd: dir.path("b"))
        try assertSameTree(src, dir.path("b/src"))
    }

    // MARK: 왕복

    func testRoundTripAllCompressionModes() throws {
        for compression in [CompressionMethod.store, .deflate] {
            for zip64 in [Zip64Mode.automatic, .always] {
                let dir = try TempDir()
                let src = try makeSampleTree(in: dir)
                var options = WriteOptions()
                options.compression = compression
                options.zip64 = zip64
                let result = try Zip.create(at: dir.path("out.zip"), from: [src], options: options)
                XCTAssertEqual(result.usedZip64, zip64 == .always)
                try Zip.extract(dir.path("out.zip"), to: dir.path("x"))
                try assertSameTree(src, dir.path("x/src"))
                try Tools.require(Tools.unzip, ["-tq", "out.zip"], cwd: dir.url)
            }
        }
    }

    func testIncompressibleDataFallsBackToStore() throws {
        let writer = ArchiveWriter()
        try writer.add(Data(randomBytes(10_000)), as: "random.bin")
        try writer.add(Data(repeating: 0, count: 10_000), as: "zeros.bin")
        try writer.add(Data(), as: "empty.bin")
        let reader = try ArchiveReader(data: try writer.finishData())
        XCTAssertEqual(reader.entries.map(\.compressionMethodID), [0, 8, 0])
        XCTAssertEqual(try reader.data(for: reader.entries[1]), Data(repeating: 0, count: 10_000))
        XCTAssertEqual(try reader.data(for: reader.entries[2]), Data())
    }

    func testMetadataPreserved() throws {
        let dir = try TempDir()
        let f = try dir.write("script.sh", "#!/bin/sh\n")
        let date = Date(timeIntervalSince1970: 1_700_000_001)
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o755), .modificationDate: date], ofItemAtPath: f.path)
        try Zip.create(at: dir.path("out.zip"), from: [f])

        let reader = try ArchiveReader(url: dir.path("out.zip"))
        XCTAssertEqual(reader.entries[0].unixPermissions, 0o755)
        XCTAssertEqual(reader.entries[0].modificationDate, date)

        try Zip.extract(dir.path("out.zip"), to: dir.path("x"))
        let a = try FileManager.default.attributesOfItem(atPath: dir.path("x/script.sh").path)
        XCTAssertEqual((a[.posixPermissions] as? NSNumber)?.intValue, 0o755)
        XCTAssertEqual(a[.modificationDate] as? Date, date)
    }

    func testCommentRoundTrip() throws {
        var options = WriteOptions()
        options.comment = "설명 comment"
        let writer = ArchiveWriter(options: options)
        try writer.add(Data("x".utf8), as: "x")
        let reader = try ArchiveReader(data: try writer.finishData())
        XCTAssertEqual(reader.comment, "설명 comment")
    }
}
