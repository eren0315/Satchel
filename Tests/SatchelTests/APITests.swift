import Foundation
import XCTest
@testable import Satchel

final class APITests: XCTestCase {

    // MARK: 대상 폴더 규칙

    func testDestinationExistsWithoutOverwrite() throws {
        let dir = try TempDir()
        try dir.write("src/a.txt", "new")
        try Zip.create(at: dir.path("z.zip"), from: [dir.path("src/a.txt")])
        try dir.write("out/a.txt", "old")
        try dir.write("out/keep.txt", "keep")

        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("out"))) { if case .destinationExists = $0 { return true }; return false }
        XCTAssertEqual(try String(contentsOf: dir.path("out/a.txt"), encoding: .utf8), "old")

        var options = ExtractOptions()
        options.overwrite = true
        try Zip.extract(dir.path("z.zip"), to: dir.path("out"), options: options)
        XCTAssertEqual(try String(contentsOf: dir.path("out/a.txt"), encoding: .utf8), "new")
        XCTAssertEqual(try String(contentsOf: dir.path("out/keep.txt"), encoding: .utf8), "keep")   // 합친다
        XCTAssertEqual(try dir.leftovers(), [])
    }

    func testCreateRefusesExistingArchive() throws {
        let dir = try TempDir()
        try dir.write("z.zip", "not mine")
        assertZipError(try ArchiveWriter(url: dir.path("z.zip"))) { if case .destinationExists = $0 { return true }; return false }
    }

    func testAbandonedWriterLeavesNoFile() throws {
        let dir = try TempDir()
        do {
            let writer = try ArchiveWriter(url: dir.path("z.zip"))
            try writer.add(Data("x".utf8), as: "x")
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dir.url.path), [])
    }

    // MARK: 항목 단위

    func testSingleEntryAPIs() throws {
        let dir = try TempDir()
        let writer = ArchiveWriter()
        try writer.addEmptyDirectory(as: "folder")
        try writer.add(Data("one".utf8), as: "folder/one.txt")
        try writer.add(Data("locked".utf8), as: "locked.txt", options: EntryOptions(encryption: .aes(), password: Password("pw")))
        let reader = try ArchiveReader(data: try writer.finishData())

        XCTAssertEqual(reader.entries.map(\.path), ["folder/", "folder/one.txt", "locked.txt"])
        XCTAssertEqual(reader.entries.map(\.kind), [.directory, .file, .file])
        XCTAssertEqual(try reader.data(for: reader.entries[1]), Data("one".utf8))

        try reader.extract(reader.entries[2], to: dir.path("single.txt"), password: Password("pw"))
        XCTAssertEqual(try String(contentsOf: dir.path("single.txt"), encoding: .utf8), "locked")
        assertZipError(try reader.extract(reader.entries[2], to: dir.path("single.txt"), password: Password("pw"))) {
            if case .destinationExists = $0 { return true }; return false
        }
        assertZipError(try reader.extract(reader.entries[2], to: dir.path("other.txt"), password: Password("no"))) {
            if case .wrongPassword = $0 { return true }; return false
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("other.txt").path))

        XCTAssertEqual(try reader.verify(Password("pw"), for: reader.entries[2]), .likelyCorrect)
        XCTAssertEqual(try reader.verify(Password("pw"), for: reader.entries[2], thorough: true), .correct)
        XCTAssertEqual(try reader.verify(Password("no"), for: reader.entries[2]), .wrong)
    }

    func testEntryFromAnotherArchiveIsRejected() throws {
        let w1 = ArchiveWriter()
        try w1.add(Data("a".utf8), as: "a")
        let w2 = ArchiveWriter()
        try w2.add(Data("b".utf8), as: "b")
        let r1 = try ArchiveReader(data: try w1.finishData())
        let r2 = try ArchiveReader(data: try w2.finishData())
        assertZipError(try r1.data(for: r2.entries[0])) { if case .unsupported = $0 { return true }; return false }
    }

    // MARK: 진행률 · 취소

    func testProgressCountsBytes() throws {
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        var write = WriteOptions()
        let wp = Progress()
        write.progress = wp
        try Zip.create(at: dir.path("z.zip"), from: [src], options: write)
        XCTAssertGreaterThan(wp.totalUnitCount, 0)
        XCTAssertEqual(wp.completedUnitCount, wp.totalUnitCount)

        var extract = ExtractOptions()
        let ep = Progress()
        extract.progress = ep
        try Zip.extract(dir.path("z.zip"), to: dir.path("x"), options: extract)
        XCTAssertEqual(ep.totalUnitCount, wp.totalUnitCount)
        XCTAssertEqual(ep.completedUnitCount, ep.totalUnitCount)
    }

    func testProgressCancel() throws {
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        try Zip.create(at: dir.path("z.zip"), from: [src])
        var options = ExtractOptions()
        let p = Progress()
        p.cancel()
        options.progress = p
        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("x"), options: options)) { $0 == .cancelled }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("x").path))
        XCTAssertEqual(try dir.leftovers(), [])

        var write = WriteOptions()
        write.progress = p
        assertZipError(try Zip.create(at: dir.path("c.zip"), from: [src], options: write)) { $0 == .cancelled }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("c.zip").path))
    }

    // MARK: 숨김 파일

    func testHiddenFilesOption() throws {
        let dir = try TempDir()
        try dir.write("src/.hidden", "h")
        try dir.write("src/visible", "v")
        var options = WriteOptions()
        options.includesHiddenFiles = false
        let result = try Zip.create(at: dir.path("z.zip"), from: [dir.path("src")], options: options)
        XCTAssertEqual(result.entries.map(\.path), ["src/", "src/visible"])
    }

    // MARK: 비밀 노출

    func testPasswordNeverPrinted() throws {
        let p = Password("TopSecret123")
        XCTAssertFalse(String(describing: p).contains("TopSecret"))
        XCTAssertFalse(String(reflecting: p).contains("TopSecret"))
        var dumped = ""
        dump(p, to: &dumped)
        XCTAssertFalse(dumped.contains("TopSecret"))
        var options = ExtractOptions()
        options.password = p
        var dumpedOptions = ""
        dump(options, to: &dumpedOptions)
        XCTAssertFalse(dumpedOptions.contains("TopSecret"))

        let writer = ArchiveWriter()
        try writer.add(Data("x".utf8), as: "x", options: EntryOptions(encryption: .aes(), password: p))
        let reader = try ArchiveReader(data: try writer.finishData())
        do {
            _ = try reader.data(for: reader.entries[0], password: Password("TopSecret124"))
        } catch {
            XCTAssertFalse(String(describing: error).contains("TopSecret"))
        }
    }
}
