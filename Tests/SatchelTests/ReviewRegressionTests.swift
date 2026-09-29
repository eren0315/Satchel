import Foundation
import XCTest
@testable import Satchel

/// 코드 리뷰에서 나온 결함의 재발 방지.
final class ReviewRegressionTests: XCTestCase {

    /// P1 — Zip64 locator 의 오프셋이 조작돼 있어도 크래시(오버플로 트랩) 없이 거부한다.
    func testHostileZip64LocatorOffsetDoesNotTrap() throws {
        var bytes = RawZip.build([RawEntry("a.txt", "x")])
        let eocd = bytes.count - 22
        var locator = ByteWriter()
        locator.u32(0x0706_4b50)
        locator.u32(0)
        locator.u64(.max)          // 덧셈하면 오버플로
        locator.u32(1)
        bytes.insert(contentsOf: locator.bytes, at: eocd)
        assertZipError(try ArchiveReader(data: Data(bytes))) { if case .corrupted = $0 { return true }; return false }
    }

    /// 빈 비밀번호는 "지원하지 않음"으로 해제 전체를 끊지 않고 "틀림"으로 본다.
    func testEmptyPasswordIsWrongNotUnsupported() async throws {
        let writer = ArchiveWriter()
        try writer.add(Data("x".utf8), as: "x", options: EntryOptions(encryption: .aes(), password: Password("pw")))
        let data = try writer.finishData()
        let reader = try ArchiveReader(data: data)
        assertZipError(try reader.data(for: reader.entries[0], password: Password(""))) {
            if case .wrongPassword = $0 { return true }; return false
        }
        XCTAssertEqual(try reader.verify(Password(""), for: reader.entries[0]), .wrong)

        let dir = try TempDir()
        try data.write(to: dir.path("p.zip"))
        let answers = ["", "pw"]
        let result = try await Zip.extract(dir.path("p.zip"), to: dir.path("out"), passwordProvider: ClosurePasswordProvider { r in
            .password(Password(answers[r.attempt - 1]))
        })
        XCTAssertEqual(result.extracted.count, 1)
    }

    /// overwrite 여도 사용자 폴더를 같은 이름의 파일로 바꾸지 않는다 (폴더 트리 재귀 삭제 방지).
    func testOverwriteNeverReplacesDirectoryWithFile() throws {
        let dir = try TempDir()
        try Data(RawZip.build([RawEntry("a", "file")])).write(to: dir.path("z.zip"))
        try dir.write("out/a/precious.txt", "keep me")
        var options = ExtractOptions()
        options.overwrite = true
        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("out"), options: options)) {
            if case .destinationExists = $0 { return true }; return false
        }
        XCTAssertEqual(try String(contentsOf: dir.path("out/a/precious.txt"), encoding: .utf8), "keep me")
        XCTAssertEqual(try dir.leftovers(), [])
    }

    /// 깊은 경로는 사전 점검에서 싸게 거부한다 (상위 경로 키의 제곱 비용 차단).
    func testTooDeepPathIsRejected() throws {
        let deep = Array(repeating: "a", count: 300).joined(separator: "/")
        let dir = try TempDir()
        try Data(RawZip.build([RawEntry(deep, "x")])).write(to: dir.path("z.zip"))
        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("out"))) {
            if case .unsafeEntryPath(_, let reason) = $0 { return reason == "path too deep" }; return false
        }
        // 10,000 개의 서로 다른 깊은 경로도 빠르게 끝난다 (트리 — 경로 길이에 비례).
        let tree = PathTree()
        let start = Date()
        for i in 0..<10_000 {
            try tree.insert(["r\(i)"] + Array(repeating: "d", count: 200), isDirectory: false, path: "p\(i)")
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 10)
    }

    /// 쓰기도 등록소를 거친다 — 뺀 스킴은 쓸 수 없다.
    func testWriterHonorsRegistry() throws {
        var options = WriteOptions()
        options.registry = ZipRegistry(codecs: [StoreCodec(), DeflateCodec()], schemes: [WinZipAESScheme()])
        options.encryption = .legacyZipCrypto
        options.password = Password("p")
        let writer = ArchiveWriter(options: options)
        assertZipError(try writer.add(Data("x".utf8), as: "x")) { if case .unsupported = $0 { return true }; return false }
    }

    /// 내장 스킴을 같은 identifier 로 교체해도 제자리에 남아 사용자 스킴을 가리지 않는다.
    func testReplacingBuiltinSchemeKeepsPriority() {
        let custom = EncryptionIdentifier(rawValue: "custom")
        struct Dummy: EncryptionScheme {
            let identifier: EncryptionIdentifier
            var requiresCRCBeforeEncryption: Bool { false }
            func matches(_ header: EntryHeader) -> Bool { true }
            func prefixLength(for header: EntryHeader) -> Int { 0 }
            func trailerLength(for header: EntryHeader) -> Int { 0 }
            func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult { .wrongPassword }
            func makeEncryptor(password: [UInt8], context: EncryptionContext) throws -> any EntryEncryptor { fatalError() }
        }
        let r = ZipRegistry.standard.registering(Dummy(identifier: custom)).registering(ZipCryptoScheme())
        XCTAssertEqual(r.schemes.map(\.identifier), [custom, .winZipAES, .zipCrypto])
    }

    /// 외부 zip 이 world-writable 권한을 강요하지 못한다.
    func testGroupAndOtherWriteBitsAreStripped() throws {
        var e = RawEntry("f", "x")
        e.externalAttributes = UInt32(0o100777) << 16
        var d = RawEntry("d/", "")
        d.externalAttributes = UInt32(0o040777) << 16
        let dir = try TempDir()
        try Data(RawZip.build([d, e])).write(to: dir.path("z.zip"))
        try Zip.extract(dir.path("z.zip"), to: dir.path("out"))
        let f = try FileManager.default.attributesOfItem(atPath: dir.path("out/f").path)
        let dd = try FileManager.default.attributesOfItem(atPath: dir.path("out/d").path)
        XCTAssertEqual((f[.posixPermissions] as? NSNumber)?.intValue, 0o755)
        XCTAssertEqual((dd[.posixPermissions] as? NSNumber)?.intValue, 0o755)
    }

    /// 압축 크기 0 · DEFLATE 인 빈 항목 (일부 도구가 이렇게 쓴다).
    func testEmptyDeflateEntryWithNoData() throws {
        var e = RawEntry("empty.txt", "")
        e.method = 8
        let reader = try ArchiveReader(data: Data(RawZip.build([e])))
        XCTAssertEqual(try reader.data(for: reader.entries[0]), Data())
        let dir = try TempDir()
        try reader.extractAll(to: dir.path("out"))
        XCTAssertEqual(try Data(contentsOf: dir.path("out/empty.txt")), Data())
    }

    /// slice-by-8 CRC 가 표준값·바이트 단위 구현과 같다.
    func testCRC32SliceBy8() {
        XCTAssertEqual(CRC32.checksum(Array("123456789".utf8)), 0xCBF4_3926)
        for length in [0, 1, 7, 8, 9, 15, 16, 17, 1_000, 65_537] {
            let bytes = randomBytes(length)
            var reference: UInt32 = 0xFFFF_FFFF
            for b in bytes { reference = CRC32.step(reference, b) }
            XCTAssertEqual(CRC32.checksum(bytes), reference ^ 0xFFFF_FFFF, "length \(length)")
            var split = CRC32()
            split.update(Array(bytes.prefix(length / 3)))
            split.update(Array(bytes.dropFirst(length / 3)))
            XCTAssertEqual(split.value, reference ^ 0xFFFF_FFFF)
        }
    }

    /// 압축이 안 되는 큰 데이터는 앞부분 판정으로 바로 저장 방식이 된다.
    func testIncompressibleProbeChoosesStore() throws {
        let writer = ArchiveWriter()
        try writer.add(Data(randomBytes(300_000)), as: "noise.bin")
        let payload = Data(String(repeating: "compress me ", count: 30_000).utf8)
        try writer.add(payload, as: "text.txt")
        let reader = try ArchiveReader(data: try writer.finishData())
        XCTAssertEqual(reader.entries.map(\.compressionMethodID), [0, 8])
        XCTAssertEqual(try reader.data(for: reader.entries[1]), payload)
    }

    /// 메모리로 푸는 API 는 기본 상한이 작다.
    func testInMemoryDefaultLimit() throws {
        let writer = ArchiveWriter()
        try writer.add(Data(repeating: 1, count: 2_000), as: "x")
        let reader = try ArchiveReader(data: try writer.finishData())
        assertZipError(try reader.data(for: reader.entries[0], limits: ExtractLimits(maxTotalUncompressedSize: 1_000))) {
            if case .limitExceeded = $0 { return true }; return false
        }
        XCTAssertEqual(ExtractLimits.inMemory.maxTotalUncompressedSize, 512 << 20)
    }

    /// 항목 단위 API 도 겹침 등 구조 문제를 거부한다.
    func testSingleEntryAPIRejectsOverlap() throws {
        var first = RawEntry("a.txt", "xxxx")
        first.compressedSizeOverride = 4 + 30 + 5
        first.uncompressedSizeOverride = 4 + 30 + 5
        let reader = try ArchiveReader(data: Data(RawZip.build([first, RawEntry("b.txt", "yyyy")])))
        assertZipError(try reader.data(for: reader.entries[1])) { if case .corrupted = $0 { return true }; return false }
    }
}
