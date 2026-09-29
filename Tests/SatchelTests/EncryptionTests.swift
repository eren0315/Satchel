import Foundation
import XCTest
@testable import Satchel

/// AES · ZipCrypto — 독립 구현(libarchive `bsdtar`, Info-ZIP `zip`/`unzip`)과 교차 검증한다.
/// 암호화·복호화를 둘 다 우리가 짜면 같은 실수(예: CTR 카운터 방향)가 서로 맞물려 왕복을 통과한다.
final class EncryptionTests: XCTestCase {
    let secret = "s3cret-비번"

    private func bsdtarArchive(_ encryption: String, in dir: TempDir, password: String) throws -> URL {
        try dir.write("in/a.txt", String(repeating: "alpha ", count: 3_000))
        try dir.write("in/b.bin", Data((0..<50_000).map { UInt8($0 % 251) }))
        try Tools.require(Tools.bsdtar, ["--format", "zip", "--options", "zip:encryption=\(encryption)",
                                        "--passphrase", password, "-cf", "out.zip", "-C", "in", "a.txt", "b.bin"], cwd: dir.url)
        return dir.path("out.zip")
    }

    // MARK: 해제 — 다른 도구가 암호화

    func testExtractBsdtarAES256AndAES128AndZipCrypto() throws {
        for (encryption, id) in [("aes256", EncryptionIdentifier.winZipAES), ("aes128", .winZipAES), ("zipcrypt", .zipCrypto)] {
            let dir = try TempDir()
            let zip = try bsdtarArchive(encryption, in: dir, password: "pw1234")
            let reader = try ArchiveReader(url: zip)
            XCTAssertTrue(reader.entries.allSatisfy { $0.encryption == id }, encryption)

            var options = ExtractOptions()
            options.password = Password("pw1234")
            try reader.extractAll(to: dir.path("x"), options: options)
            XCTAssertEqual(try Data(contentsOf: dir.path("x/a.txt")), try Data(contentsOf: dir.path("in/a.txt")), encryption)
            XCTAssertEqual(try Data(contentsOf: dir.path("x/b.bin")), try Data(contentsOf: dir.path("in/b.bin")), encryption)
        }
    }

    func testWrongAndMissingPassword() throws {
        for encryption in ["aes256", "zipcrypt"] {
            let dir = try TempDir()
            let zip = try bsdtarArchive(encryption, in: dir, password: "right")
            assertZipError(try Zip.extract(zip, to: dir.path("x"))) { if case .passwordRequired = $0 { return true }; return false }
            var options = ExtractOptions()
            options.password = Password("wrong")
            assertZipError(try Zip.extract(zip, to: dir.path("x"), options: options)) { if case .wrongPassword = $0 { return true }; return false }
            XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("x").path), "nothing left behind (\(encryption))")
            XCTAssertEqual(try dir.leftovers(), [])
        }
    }

    func testExtractInfoZipPassword() throws {
        let dir = try TempDir()
        try dir.write("secret.txt", "classified\n")
        try Tools.require(Tools.zip, ["-q", "-P", "zippw", "out.zip", "secret.txt"], cwd: dir.url)
        let reader = try ArchiveReader(url: dir.path("out.zip"))
        XCTAssertEqual(reader.entries[0].encryption, .zipCrypto)
        XCTAssertEqual(try reader.data(for: reader.entries[0], password: Password("zippw")), Data("classified\n".utf8))
    }

    func testCP949PasswordCandidate() throws {
        let dir = try TempDir()
        try dir.write("k.txt", "korean password\n")
        let pw = "비밀"
        let cp949 = try XCTUnwrap(pw.data(using: TextCodec.cp949))
        let r = try Tools.sh("\(Tools.zip ?? "zip") -q -P \"$(printf '\(printfOctal([UInt8](cp949)))')\" out.zip k.txt", cwd: dir.url)
        XCTAssertEqual(r.status, 0, r.stderr)
        let reader = try ArchiveReader(url: dir.path("out.zip"))
        // 기본 후보: UTF-8 → CP949 → CP437. UTF-8 은 빠른 확인에서 떨어지고 CP949 가 맞는다.
        XCTAssertEqual(try reader.data(for: reader.entries[0], password: Password(pw)), Data("korean password\n".utf8))
        assertZipError(try reader.data(for: reader.entries[0], password: Password(pw, encodings: [.utf8]))) {
            if case .wrongPassword = $0 { return true }; return false
        }
    }

    func testNFDPasswordCandidate() throws {
        // Process 인수는 NFD 로 넘어간다 → bsdtar 는 NFD 바이트로 암호화한다. NFC 로 입력해도 풀려야 한다.
        let dir = try TempDir()
        let zip = try bsdtarArchive("aes256", in: dir, password: "비번")
        let reader = try ArchiveReader(url: zip)
        XCTAssertEqual(try reader.verify(Password("비번".precomposedStringWithCanonicalMapping), for: reader.entries[0], thorough: true), .correct)
    }

    // MARK: 생성 — Satchel 이 암호화, 다른 도구가 해제

    func testCreatedAESReadableByBsdtar() throws {
        for strength in AESStrength.allCases {
            let dir = try TempDir()
            let src = try makeSampleTree(in: dir)
            var options = WriteOptions()
            options.encryption = .aes(strength)
            options.password = Password(secret)
            try Zip.create(at: dir.path("out.zip"), from: [src], options: options)

            try dir.mkdir("b")
            // Process 인수는 NFD 로 바뀌므로 셸 printf 로 NFC 바이트를 그대로 넘긴다.
            let nfc = printfOctal(Array(secret.precomposedStringWithCanonicalMapping.utf8))
            let r = try Tools.sh("\(Tools.bsdtar ?? "bsdtar") --passphrase \"$(printf '\(nfc)')\" -xf ../out.zip", cwd: dir.path("b"))
            XCTAssertEqual(r.status, 0, "\(strength): \(r.stderr)")
            XCTAssertEqual(try TempDir.snapshot(src), try TempDir.snapshot(dir.path("b/src")), "\(strength)")

            let wrong = try Tools.run(Tools.bsdtar, ["--passphrase", "nope", "-xf", "../out.zip"], cwd: dir.path("b"))
            XCTAssertNotEqual(wrong.status, 0)
        }
    }

    func testCreatedZipCryptoReadableByUnzip() throws {
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        var options = WriteOptions()
        options.encryption = .legacyZipCrypto
        options.password = Password("legacy")
        try Zip.create(at: dir.path("out.zip"), from: [src], options: options)
        try Tools.require(Tools.unzip, ["-tq", "-P", "legacy", "out.zip"], cwd: dir.url)
        try dir.mkdir("u")
        try Tools.require(Tools.unzip, ["-q", "-P", "legacy", "../out.zip"], cwd: dir.path("u"))
        XCTAssertEqual(try TempDir.snapshot(src), try TempDir.snapshot(dir.path("u/src")))
    }

    func testCreatedAESVerifiedBy7Zip() throws {
        guard Tools.sevenZip != nil else { throw XCTSkip("7zz not installed") }
        let dir = try TempDir()
        let src = try makeSampleTree(in: dir)
        var options = WriteOptions()
        options.encryption = .aes(.bits256)
        options.password = Password(secret)
        try Zip.create(at: dir.path("out.zip"), from: [src], options: options)
        try Tools.require(Tools.sevenZip, ["t", "-p\(secret)", "out.zip"], cwd: dir.url)
    }

    // MARK: 왕복 · 조합

    func testRoundTripEveryScheme() throws {
        let methods: [EncryptionMethod] = [.aes(.bits128), .aes(.bits192), .aes(.bits256), .legacyZipCrypto]
        for method in methods {
            for compression in [CompressionMethod.store, .deflate] {
                var options = WriteOptions()
                options.encryption = method
                options.compression = compression
                options.password = Password(secret)
                let writer = ArchiveWriter(options: options)
                let payload = Data(String(repeating: "payload ", count: 10_000).utf8)
                try writer.add(payload, as: "p.txt")
                try writer.add(Data(), as: "empty.txt")
                let reader = try ArchiveReader(data: try writer.finishData())
                XCTAssertEqual(try reader.data(for: reader.entries[0], password: Password(secret)), payload, "\(method) \(compression)")
                XCTAssertEqual(try reader.data(for: reader.entries[1], password: Password(secret)), Data(), "\(method) empty")
                XCTAssertEqual(try reader.verify(Password(secret), for: reader.entries[0], thorough: true), .correct)
                XCTAssertEqual(try reader.verify(Password("x"), for: reader.entries[0]), .wrong)
            }
        }
    }

    func testAESStoresNoCRCAndRealMethod() throws {
        var options = WriteOptions()
        options.encryption = .aes()
        options.password = Password(secret)
        let writer = ArchiveWriter(options: options)
        try writer.add(Data(String(repeating: "abc", count: 1000).utf8), as: "a.txt")
        let reader = try ArchiveReader(data: try writer.finishData())
        XCTAssertNil(reader.entries[0].crc32)                  // AE-2
        XCTAssertEqual(reader.entries[0].compressionMethodID, 8) // 99 가 아닌 실제 방식
    }

    func testTamperedAESFailsAuthentication() throws {
        var options = WriteOptions()
        options.encryption = .aes()
        options.password = Password(secret)
        options.compression = .store
        let writer = ArchiveWriter(options: options)
        try writer.add(Data(String(repeating: "z", count: 500).utf8), as: "a.txt")
        var bytes = [UInt8](try writer.finishData())
        let reader0 = try ArchiveReader(data: Data(bytes))
        // 암호문 한가운데 1비트 뒤집기
        let dataStart = Int(reader0.dataOffsets[0]) + 18
        bytes[dataStart + 100] ^= 0x01
        let reader = try ArchiveReader(data: Data(bytes))
        assertZipError(try reader.data(for: reader.entries[0], password: Password(secret))) {
            if case .corrupted(_, let reason) = $0 { return reason.contains("authentication") }; return false
        }
    }

    func testPerEntryPasswordsAndMixedArchive() throws {
        let writer = ArchiveWriter()
        try writer.add(Data("open".utf8), as: "open.txt")
        try writer.add(Data("one".utf8), as: "one.txt", options: EntryOptions(encryption: .aes(), password: Password("1111")))
        try writer.add(Data("two".utf8), as: "two.txt", options: EntryOptions(encryption: .legacyZipCrypto, password: Password("2222")))
        let reader = try ArchiveReader(data: try writer.finishData())
        XCTAssertEqual(reader.entries.map(\.encryption), [nil, .winZipAES, .zipCrypto])
        XCTAssertEqual(try reader.data(for: reader.entries[0]), Data("open".utf8))
        XCTAssertEqual(try reader.data(for: reader.entries[1], password: Password("1111")), Data("one".utf8))
        XCTAssertEqual(try reader.data(for: reader.entries[2], password: Password("2222")), Data("two".utf8))
    }

    func testDisallowedEncryption() throws {
        let writer = ArchiveWriter()
        try writer.add(Data("x".utf8), as: "x", options: EntryOptions(encryption: .legacyZipCrypto, password: Password("p")))
        let dir = try TempDir()
        try writer.finishData().write(to: dir.path("z.zip"))
        var options = ExtractOptions()
        options.password = Password("p")
        options.allowedEncryption = [.winZipAES]
        assertZipError(try Zip.extract(dir.path("z.zip"), to: dir.path("x"), options: options)) { $0 == .disallowedEncryption(.zipCrypto) }
    }

    func testEncryptionWithoutPasswordIsRejected() throws {
        var options = WriteOptions()
        options.encryption = .aes()
        let writer = ArchiveWriter(options: options)
        assertZipError(try writer.add(Data("x".utf8), as: "x")) { if case .passwordRequired = $0 { return true }; return false }
        options.password = Password("")
        let writer2 = ArchiveWriter(options: options)
        assertZipError(try writer2.add(Data("x".utf8), as: "x")) { if case .unsupported = $0 { return true }; return false }
    }
}
