import Foundation
import Security

/// 전통 PKWARE 암호 (ZipCrypto).
///
/// ⚠️ **깨진 방식**이다 — 알려진 평문 공격으로 비밀번호 없이 풀린다. 해제는 호환을 위해 지원하고,
/// 생성은 `EncryptionMethod.legacyZipCrypto` 를 직접 지정했을 때만 한다.
///
/// 무결성 수단이 CRC 뿐이라 틀린 비밀번호와 손상을 구분할 수 없다 → CRC 불일치를 "비밀번호 틀림"으로 본다.
public struct ZipCryptoScheme: EncryptionScheme {
    public init() {}

    public var identifier: EncryptionIdentifier { .zipCrypto }
    public var requiresCRCBeforeEncryption: Bool { true }

    static let headerLength = 12

    public func matches(_ header: EntryHeader) -> Bool {
        header.isEncrypted
            && header.generalPurposeFlags & GeneralPurposeFlag.strongEncryption == 0
            && header.compressionMethodID != WinZipAESScheme.methodID
    }

    public func prefixLength(for header: EntryHeader) -> Int { Self.headerLength }
    public func trailerLength(for header: EntryHeader) -> Int { 0 }

    public func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult {
        guard !password.isEmpty else { throw ZipError.unsupported("empty password") }
        guard prefix.count == Self.headerLength else {
            throw ZipError.corrupted(entry: nil, reason: "truncated ZipCrypto header")
        }
        var keys = ZipCryptoKeys(password: password)
        let plain = keys.decrypt(prefix)
        let check = plain[Self.headerLength - 1]
        let crcByte = UInt8(truncatingIfNeeded: header.crc32 >> 24)
        let timeByte = UInt8(truncatingIfNeeded: header.dosTime >> 8)
        // data descriptor 를 쓴 항목은 도구에 따라 수정 시각 또는 CRC 상위 바이트를 쓴다.
        let ok = header.usesDataDescriptor ? (check == timeByte || check == crcByte) : check == crcByte
        return ok ? .ready(ZipCryptoDecryptor(keys: keys)) : .wrongPassword
    }

    public func makeEncryptor(password: [UInt8], context: EncryptionContext) throws -> any EntryEncryptor {
        guard !password.isEmpty else { throw ZipError.unsupported("empty password") }
        guard let crc = context.crc32 else { throw ZipError.unsupported("ZipCrypto requires CRC before encryption") }
        var header = [UInt8](repeating: 0, count: Self.headerLength)
        let status = header.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, Self.headerLength - 1, $0.baseAddress!) }
        guard status == errSecSuccess else { throw ZipError.unsupported("secure random unavailable") }
        header[Self.headerLength - 1] = UInt8(truncatingIfNeeded: crc >> 24)
        var keys = ZipCryptoKeys(password: password)
        let encryptedHeader = keys.encrypt(header)
        return ZipCryptoEncryptor(keys: keys, encryptedHeader: encryptedHeader)
    }
}

struct ZipCryptoKeys {
    private var k0: UInt32 = 0x1234_5678
    private var k1: UInt32 = 0x2345_6789
    private var k2: UInt32 = 0x3456_7890

    init(password: [UInt8]) {
        for b in password { update(b) }
    }

    private mutating func update(_ byte: UInt8) {
        k0 = CRC32.step(k0, byte)
        k1 = (k1 &+ (k0 & 0xFF)) &* 134_775_813 &+ 1
        k2 = CRC32.step(k2, UInt8(truncatingIfNeeded: k1 >> 24))
    }

    private var streamByte: UInt8 {
        let t = (k2 | 2) & 0xFFFF
        return UInt8(truncatingIfNeeded: (t &* (t ^ 1)) >> 8)
    }

    mutating func decrypt(_ input: [UInt8]) -> [UInt8] {
        var out = input
        for i in out.indices {
            let p = out[i] ^ streamByte
            update(p)
            out[i] = p
        }
        return out
    }

    mutating func encrypt(_ input: [UInt8]) -> [UInt8] {
        var out = input
        for i in out.indices {
            let p = out[i]
            out[i] = p ^ streamByte
            update(p)
        }
        return out
    }
}

final class ZipCryptoDecryptor: EntryDecryptor {
    private var keys: ZipCryptoKeys
    init(keys: ZipCryptoKeys) { self.keys = keys }
    func process(_ input: [UInt8]) throws -> [UInt8] { keys.decrypt(input) }
    func finish() throws -> [UInt8] { [] }
    func verify(trailer: [UInt8]) throws {}
    var providesIntegrity: Bool { false }
    var integrityFailureIndicatesWrongPassword: Bool { true }
}

final class ZipCryptoEncryptor: EntryEncryptor {
    private var keys: ZipCryptoKeys
    private let encryptedHeader: [UInt8]
    let headerAdjustment = HeaderAdjustment(storesCRC: true, versionNeededToExtract: 20,
                                            generalPurposeFlags: GeneralPurposeFlag.encrypted)

    init(keys: ZipCryptoKeys, encryptedHeader: [UInt8]) {
        self.keys = keys
        self.encryptedHeader = encryptedHeader
    }

    func prefix() -> [UInt8] { encryptedHeader }
    func process(_ input: [UInt8]) throws -> [UInt8] { keys.encrypt(input) }
    func finish() throws -> [UInt8] { [] }
    func trailer() throws -> [UInt8] { [] }
}
