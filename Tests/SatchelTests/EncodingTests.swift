import Foundation
import XCTest
@testable import Satchel

final class EncodingTests: XCTestCase {
    let korean = "한글 문서/보고서.txt"

    func testCP949NameWithoutUTF8Flag() throws {
        let raw = [UInt8](try XCTUnwrap(korean.data(using: TextCodec.cp949)))
        let reader = try ArchiveReader(data: Data(RawZip.build([RawEntry(rawName: raw, data: Array("x".utf8))])))
        XCTAssertEqual(reader.entries[0].path, korean)

        let dir = try TempDir()
        try reader.extractAll(to: dir.path("out"))
        XCTAssertEqual(try String(contentsOf: dir.path("out/\(korean)"), encoding: .utf8), "x")
    }

    func testUTF8WithoutFlag() throws {
        let reader = try ArchiveReader(data: Data(RawZip.build([RawEntry(korean, "x")])))
        XCTAssertEqual(reader.entries[0].path, korean)
    }

    func testCP437Fallback() throws {
        // 0x82 = é (CP437). CP949 로는 해석되지 않는 단독 바이트.
        let raw: [UInt8] = Array("caf".utf8) + [0x82]
        let reader = try ArchiveReader(data: Data(RawZip.build([RawEntry(rawName: raw, data: [])])))
        XCTAssertEqual(reader.entries[0].path, "café")
    }

    func testForcedEncoding() throws {
        let raw = [UInt8](try XCTUnwrap(korean.data(using: TextCodec.cp949)))
        var options = ReadOptions()
        options.filenameEncoding = .cp437
        let reader = try ArchiveReader(data: Data(RawZip.build([RawEntry(rawName: raw, data: [])])), options: options)
        XCTAssertNotEqual(reader.entries[0].path, korean)
    }

    func testUnicodePathExtraUsedOnlyWhenCRCMatches() throws {
        let raw = Array("legacy-name.txt".utf8)
        var good = RawEntry(rawName: raw, data: [])
        good.extra = [ExtraField.unicodePath(name: "유니코드.txt", originalNameBytes: raw)]
        var stale = RawEntry(rawName: Array("other.txt".utf8), data: [])
        stale.extra = [ExtraField.unicodePath(name: "무시.txt", originalNameBytes: raw)]   // CRC 가 다른 이름 기준
        let reader = try ArchiveReader(data: Data(RawZip.build([good, stale])))
        XCTAssertEqual(reader.entries.map(\.path), ["유니코드.txt", "other.txt"])
    }

    func testWriteCP949WithUnicodePathExtra() throws {
        var options = WriteOptions()
        options.filenameEncoding = .cp949
        let writer = ArchiveWriter(options: options)
        try writer.add(Data("내용".utf8), as: korean)
        try writer.add(Data("ascii".utf8), as: "plain.txt")
        let data = try writer.finishData()

        let reader = try ArchiveReader(data: data)
        XCTAssertEqual(reader.entries.map(\.path), [korean, "plain.txt"])
        XCTAssertEqual(reader.entries[0].rawPath, [UInt8](korean.data(using: TextCodec.cp949)!))
        XCTAssertTrue(reader.entries[0].extraFields.contains { $0.id == 0x7075 })
        XCTAssertFalse(reader.entries[1].extraFields.contains { $0.id == 0x7075 })

        // 유니코드 경로 extra 를 모르는 도구도 CP949 로 읽으면 맞다.
        let dir = try TempDir()
        try data.write(to: dir.path("k.zip"))
        let py = try Tools.python("import zipfile; print(zipfile.ZipFile('k.zip', metadata_encoding='cp949').namelist()[0])", cwd: dir.url)
        XCTAssertEqual(py.status, 0, py.stderr)
        XCTAssertEqual(String(decoding: py.stdout, as: UTF8.self).trimmingCharacters(in: .newlines), korean)
    }

    func testCP949CannotEncodeEmoji() throws {
        var options = WriteOptions()
        options.filenameEncoding = .cp949
        let writer = ArchiveWriter(options: options)
        assertZipError(try writer.add(Data(), as: "😀.txt")) { if case .filenameEncodingFailed = $0 { return true }; return false }
    }

    func testNFDNamesAreNormalizedToNFC() throws {
        let nfd = "자모.txt".decomposedStringWithCanonicalMapping
        let writer = ArchiveWriter()
        try writer.add(Data(), as: nfd)
        let reader = try ArchiveReader(data: try writer.finishData())
        XCTAssertEqual(reader.entries[0].rawPath, Array("자모.txt".precomposedStringWithCanonicalMapping.utf8))

        var keep = WriteOptions()
        keep.normalizesFilenamesToNFC = false
        let writer2 = ArchiveWriter(options: keep)
        try writer2.add(Data(), as: nfd)
        XCTAssertEqual(try ArchiveReader(data: try writer2.finishData()).entries[0].rawPath, Array(nfd.utf8))
    }
}
