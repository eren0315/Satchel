import Foundation
import XCTest
@testable import Satchel

/// 외부에서 받은 zip 을 믿지 않는다 — 공격 zip 은 전부 원시 바이트로 직접 만든다.
final class SafetyTests: XCTestCase {

    private func extract(_ bytes: [UInt8], options: ExtractOptions = .init(), into dir: TempDir) throws {
        try Data(bytes).write(to: dir.path("evil.zip"))
        try Zip.extract(dir.path("evil.zip"), to: dir.path("out"), options: options)
    }

    private func assertRejected(_ entries: [RawEntry], file: StaticString = #filePath, line: UInt = #line,
                                _ check: (ZipError) -> Bool) throws {
        let dir = try TempDir()
        assertZipError(try extract(RawZip.build(entries), into: dir), file: file, line: line, check)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("out").path), "destination created", file: file, line: line)
        XCTAssertEqual(try dir.leftovers(), [], file: file, line: line)
        let outside = try FileManager.default.contentsOfDirectory(atPath: dir.url.path).filter { $0 != "evil.zip" }
        XCTAssertEqual(outside, [], "wrote outside destination", file: file, line: line)
    }

    private func isUnsafe(_ e: ZipError) -> Bool { if case .unsafeEntryPath = e { return true }; return false }
    private func isCorrupted(_ e: ZipError) -> Bool { if case .corrupted = e { return true }; return false }

    func testPathTraversal() throws {
        try assertRejected([RawEntry("ok.txt", "fine"), RawEntry("../escape.txt", "evil")], isUnsafe)
        try assertRejected([RawEntry("a/../../escape.txt", "evil")], isUnsafe)
        try assertRejected([RawEntry("..\\escape.txt", "evil")], isUnsafe)
    }

    func testAbsoluteAndDrivePaths() throws {
        try assertRejected([RawEntry("/tmp/escape.txt", "evil")], isUnsafe)
        try assertRejected([RawEntry("C:\\escape.txt", "evil")], isUnsafe)
        try assertRejected([RawEntry("\\\\server\\share.txt", "evil")], isUnsafe)
    }

    func testControlCharactersAndEmptyNames() throws {
        try assertRejected([RawEntry("bad\u{01}name", "x")], isUnsafe)
        try assertRejected([RawEntry("./", "")], isUnsafe)
    }

    func testSymlinkEntry() throws {
        var link = RawEntry("link", "/etc/passwd")
        link.externalAttributes = UInt32(0o120777) << 16
        try assertRejected([link], isUnsafe)
    }

    func testDuplicatesCaseAndNormalization() throws {
        try assertRejected([RawEntry("a.txt", "1"), RawEntry("a.txt", "2")], isUnsafe)
        try assertRejected([RawEntry("Readme.TXT", "1"), RawEntry("readme.txt", "2")], isUnsafe)
        let nfc = "한.txt".precomposedStringWithCanonicalMapping
        let nfd = "한.txt".decomposedStringWithCanonicalMapping
        XCTAssertNotEqual(Array(nfc.utf8), Array(nfd.utf8))
        try assertRejected([RawEntry(nfc, "1"), RawEntry(nfd, "2")], isUnsafe)
    }

    func testFileAndDirectoryShareName() throws {
        try assertRejected([RawEntry("a", "file"), RawEntry("a/b.txt", "child")], isUnsafe)
        try assertRejected([RawEntry("a/", ""), RawEntry("a", "file")], isUnsafe)
    }

    func testLocalNameMismatch() throws {
        var e = RawEntry("innocent.txt", "x")
        e.localName = Array("../evil.txt".utf8)
        try assertRejected([e], isCorrupted)
    }

    func testDeclaredSizeSmallerThanData() throws {
        var e = RawEntry("bomb.txt", String(repeating: "A", count: 1000))
        e.uncompressedSizeOverride = 10
        try assertRejected([e], isCorrupted)
    }

    func testCompressionRatioLimit() throws {
        let writer = ArchiveWriter()
        let block = randomBytes(100)
        try writer.add(Data((0..<20_000).flatMap { _ in block }), as: "zeros.bin")   // 비율 약 80:1
        let dir = try TempDir()
        try writer.finishData().write(to: dir.path("z.zip"))
        var options = ExtractOptions()
        options.limits.maxCompressionRatio = 50
        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("out"), options: options)) {
            if case .limitExceeded = $0 { return true }; return false
        }
        options.limits = ExtractLimits(maxTotalUncompressedSize: 1_000_000)
        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("out"), options: options)) {
            if case .limitExceeded = $0 { return true }; return false
        }
        try Zip.extract(dir.path("z.zip"), to: dir.path("out"))
    }

    func testOverlappingEntries() throws {
        // 첫 항목의 압축 크기가 다음 항목의 로컬 헤더까지 덮는다 (겹침 폭탄의 기본형).
        var first = RawEntry("a.txt", "xxxx")
        first.compressedSizeOverride = 4 + 30 + 5
        first.uncompressedSizeOverride = 4 + 30 + 5
        try assertRejected([first, RawEntry("b.txt", "yyyy")], isCorrupted)
    }

    func testTruncatedArchive() throws {
        let dir = try TempDir()
        let bytes = RawZip.build([RawEntry("a.txt", String(repeating: "x", count: 1000))])
        try Data(bytes.prefix(bytes.count - 30)).write(to: dir.path("t.zip"))
        assertZipError(try ArchiveReader(url: dir.path("t.zip"))) { self.isCorrupted($0) }
    }

    func testFakeEndRecordInsideComment() throws {
        // 주석 안의 가짜 EOCD 시그니처는 무시하고 진짜 EOCD 를 찾아야 한다.
        let fake: [UInt8] = [0x50, 0x4b, 0x05, 0x06] + [UInt8](repeating: 0, count: 18)
        let bytes = RawZip.build([RawEntry("a.txt", "real")], comment: fake)
        let reader = try ArchiveReader(data: Data(bytes))
        XCTAssertEqual(reader.entries.map(\.path), ["a.txt"])
    }

    func testMultiDiskAndStrongEncryptionUnsupported() throws {
        let dir = try TempDir()
        assertZipError(try ArchiveReader(data: Data(RawZip.build([RawEntry("a", "x")], eocdDisk: 1)))) {
            if case .unsupported = $0 { return true }; return false
        }
        var strong = RawEntry("s.txt", "x")
        strong.flags = 0x0041
        assertZipError(try extract(RawZip.build([strong]), into: dir)) { if case .unsupported = $0 { return true }; return false }
    }

    func testUnknownCompressionMethod() throws {
        var e = RawEntry("a.txt", "x")
        e.method = 14   // LZMA
        let dir = try TempDir()
        assertZipError(try extract(RawZip.build([e]), into: dir)) { if case .unsupported = $0 { return true }; return false }
    }

    func testAtomicityOnCRCFailure() throws {
        var bad = RawEntry("z-bad.txt", "payload")
        bad.crc = 0xDEAD_BEEF
        try assertRejected([RawEntry("a-good.txt", "fine"), bad], isCorrupted)
    }

    func testExistingSymlinkInDestinationIsRefused() throws {
        let dir = try TempDir()
        try dir.mkdir("outside")
        try dir.mkdir("out")
        try FileManager.default.createSymbolicLink(at: dir.path("out/sub"), withDestinationURL: dir.path("outside"))
        try Data(RawZip.build([RawEntry("sub/x.txt", "evil")])).write(to: dir.path("e.zip"))
        assertZipError(try Zip.extract(dir.path("e.zip"), to: dir.path("out"))) { self.isUnsafe($0) }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.path("outside").path), [])
    }

    func testSetuidBitsAreStripped() throws {
        var e = RawEntry("tool", "#!/bin/sh\n")
        e.externalAttributes = UInt32(0o104755) << 16   // setuid
        let dir = try TempDir()
        try extract(RawZip.build([e]), into: dir)
        let a = try FileManager.default.attributesOfItem(atPath: dir.path("out/tool").path)
        XCTAssertEqual((a[.posixPermissions] as? NSNumber)?.intValue, 0o755)
    }

    func testWriterRejectsUnsafeNames() throws {
        let writer = ArchiveWriter()
        assertZipError(try writer.add(Data(), as: "../x")) { self.isUnsafe($0) }
        assertZipError(try writer.add(Data(), as: "/abs")) { self.isUnsafe($0) }
        try writer.add(Data(), as: "dup")
        assertZipError(try writer.add(Data(), as: "DUP")) { self.isUnsafe($0) }
        assertZipError(try writer.add(Data(), as: "dup/child")) { self.isUnsafe($0) }
    }
}
