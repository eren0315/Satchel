import Foundation
import XCTest
import Satchel   // 공개 API 만으로 확장할 수 있는지 확인한다 (@testable 아님)

/// 테스트용 사용자 코덱 — 비트를 반전하는 "압축".
struct InvertBitsCodec: CompressionCodec {
    var methodID: UInt16 { 0x7A01 }
    var versionNeededToExtract: UInt16 { 20 }
    func makeCompressor() throws -> any ByteTransform { Flip() }
    func makeDecompressor() throws -> any ByteTransform { Flip() }

    final class Flip: ByteTransform {
        func process(_ input: [UInt8]) throws -> [UInt8] { input.map { ~$0 } }
        func finish() throws -> [UInt8] { [] }
    }
}

/// 테스트용 사용자 스킴 — 비밀번호 첫 바이트로 XOR, 앞에 확인 바이트 1개.
struct XORScheme: EncryptionScheme {
    static let id = EncryptionIdentifier(rawValue: "test-xor")
    static let extraID: UInt16 = 0xCAFE

    var identifier: EncryptionIdentifier { Self.id }
    var requiresCRCBeforeEncryption: Bool { false }

    func matches(_ header: EntryHeader) -> Bool { header.isEncrypted && header.extraField(Self.extraID) != nil }
    func prefixLength(for header: EntryHeader) -> Int { 1 }
    func trailerLength(for header: EntryHeader) -> Int { 0 }

    func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult {
        prefix == [password[0] ^ 0x5A] ? .ready(Dec(key: password[0])) : .wrongPassword
    }

    func makeEncryptor(password: [UInt8], context: EncryptionContext) throws -> any EntryEncryptor {
        Enc(key: password[0])
    }

    final class Dec: EntryDecryptor {
        let key: UInt8
        init(key: UInt8) { self.key = key }
        func process(_ input: [UInt8]) throws -> [UInt8] { input.map { $0 ^ key } }
        func finish() throws -> [UInt8] { [] }
        func verify(trailer: [UInt8]) throws {}
        var providesIntegrity: Bool { false }
    }

    final class Enc: EntryEncryptor {
        let key: UInt8
        init(key: UInt8) { self.key = key }
        var headerAdjustment: HeaderAdjustment {
            HeaderAdjustment(extraFields: [ExtraField(id: XORScheme.extraID, data: [])])
        }
        func prefix() -> [UInt8] { [key ^ 0x5A] }
        func process(_ input: [UInt8]) throws -> [UInt8] { input.map { $0 ^ key } }
        func finish() throws -> [UInt8] { [] }
        func trailer() throws -> [UInt8] { [] }
    }
}

final class ExtensionTests: XCTestCase {
    func testCustomCodecAndSchemeRoundTrip() throws {
        let registry = ZipRegistry.standard.registering(InvertBitsCodec()).registering(XORScheme())
        var write = WriteOptions()
        write.registry = registry
        write.compression = .custom(methodID: 0x7A01)
        write.encryption = .custom(XORScheme.id)
        write.password = Password("k")
        let writer = ArchiveWriter(options: write)
        let payload = Data("custom pipeline ✓".utf8)
        try writer.add(payload, as: "c.txt")
        let data = try writer.finishData()

        var read = ReadOptions()
        read.registry = registry
        let reader = try ArchiveReader(data: data, options: read)
        XCTAssertEqual(reader.entries[0].encryption, XORScheme.id)
        XCTAssertEqual(reader.entries[0].compressionMethodID, 0x7A01)
        XCTAssertEqual(try reader.data(for: reader.entries[0], password: Password("k")), payload)
        XCTAssertThrowsError(try reader.data(for: reader.entries[0], password: Password("j")))

        // 등록하지 않은 쪽에서는 명시적으로 실패한다.
        let plain = try ArchiveReader(data: data)
        XCTAssertThrowsError(try plain.data(for: plain.entries[0], password: Password("k"))) { error in
            guard case ZipError.unsupported = error else { return XCTFail("\(error)") }
        }
    }

    func testRegistryReplacesSameIdentifier() {
        let r = ZipRegistry.standard.registering(StoreCodec()).registering(WinZipAESScheme(strength: .bits128))
        XCTAssertEqual(r.codecs.count, ZipRegistry.standard.codecs.count)
        XCTAssertEqual(r.schemes.count, ZipRegistry.standard.schemes.count)
    }
}
