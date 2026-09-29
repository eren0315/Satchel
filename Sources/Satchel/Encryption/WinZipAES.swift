import CommonCrypto
import Foundation
import Security

/// WinZip AES (AE-1 · AE-2, 128/192/256).
///
/// - 쓰기는 항상 AE-2 (CRC 를 0 으로 두고 무결성은 HMAC 이 맡는다).
/// - 🔴 CTR 카운터는 **1 에서 시작해 little-endian 으로 증가**한다. CommonCrypto 의 `kCCModeCTR` 은
///   big-endian 이라 그대로 쓰면 결과가 틀린다 → ECB 로 카운터 블록을 직접 암호화한다.
public struct WinZipAESScheme: EncryptionScheme {
    public let strength: AESStrength

    /// `strength` 는 쓰기에만 쓰인다. 읽기는 헤더의 강도를 따른다.
    public init(strength: AESStrength = .bits256) {
        self.strength = strength
    }

    public var identifier: EncryptionIdentifier { .winZipAES }
    public var requiresCRCBeforeEncryption: Bool { false }

    static let methodID: UInt16 = 99
    static let authenticationCodeLength = 10
    static let iterations: UInt32 = 1000

    struct AESExtra {
        let vendorVersion: UInt16
        let strengthCode: UInt8
        let compressionMethodID: UInt16
    }

    static func parseExtra(_ header: EntryHeader) -> AESExtra? {
        guard let f = header.extraField(ExtraFieldID.winZipAES), f.data.count >= 7 else { return nil }
        var r = ByteReader(f.data)
        guard let version = try? r.u16(), let vendor = try? r.take(2), vendor == [0x41, 0x45],
              let code = try? r.u8(), let method = try? r.u16() else { return nil }
        return AESExtra(vendorVersion: version, strengthCode: code, compressionMethodID: method)
    }

    static func vendorVersion(of header: EntryHeader) -> UInt16? { parseExtra(header)?.vendorVersion }

    public func matches(_ header: EntryHeader) -> Bool {
        header.isEncrypted && header.compressionMethodID == Self.methodID && Self.parseExtra(header) != nil
    }

    public func actualCompressionMethodID(for header: EntryHeader) -> UInt16 {
        Self.parseExtra(header)?.compressionMethodID ?? header.compressionMethodID
    }

    /// AE-2 는 CRC 를 0 으로 저장한다.
    public func storesCRC(for header: EntryHeader) -> Bool { Self.vendorVersion(of: header) != 2 }

    public func prefixLength(for header: EntryHeader) -> Int {
        let s = Self.parseExtra(header).flatMap { AESStrength(code: $0.strengthCode) } ?? .bits256
        return s.saltLength + 2
    }

    public func trailerLength(for header: EntryHeader) -> Int { Self.authenticationCodeLength }

    public func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult {
        guard let extra = Self.parseExtra(header) else {
            throw ZipError.corrupted(entry: nil, reason: "missing AES extra field")
        }
        guard extra.vendorVersion == 1 || extra.vendorVersion == 2 else {
            throw ZipError.unsupported("AES vendor version \(extra.vendorVersion)")
        }
        guard let s = AESStrength(code: extra.strengthCode) else {
            throw ZipError.unsupported("AES strength code \(extra.strengthCode)")
        }
        guard prefix.count == s.saltLength + 2 else {
            throw ZipError.corrupted(entry: nil, reason: "truncated AES header")
        }
        let salt = Array(prefix[0..<s.saltLength])
        let verifier = Array(prefix[s.saltLength...])
        let keys = try AESKeys.derive(password: password, salt: salt, strength: s)
        guard constantTimeEqual(keys.verifier, verifier) else { return .wrongPassword }
        return .ready(try AESEntryDecryptor(keys: keys, checksCRC: extra.vendorVersion == 1))
    }

    public func makeEncryptor(password: [UInt8], context: EncryptionContext) throws -> any EntryEncryptor {
        var salt = [UInt8](repeating: 0, count: strength.saltLength)
        let status = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw ZipError.unsupported("secure random unavailable") }
        let keys = try AESKeys.derive(password: password, salt: salt, strength: strength)
        return try AESEntryEncryptor(keys: keys, salt: salt, strength: strength,
                                     actualMethodID: context.compressionMethodID)
    }
}

/// 파생 키. 쓰고 나면(해제될 때) 0 으로 덮는다 — 최선의 노력.
final class AESKeys {
    private(set) var encryptionKey: [UInt8]
    private(set) var authenticationKey: [UInt8]
    let verifier: [UInt8]

    init(encryptionKey: [UInt8], authenticationKey: [UInt8], verifier: [UInt8]) {
        self.encryptionKey = encryptionKey
        self.authenticationKey = authenticationKey
        self.verifier = verifier
    }

    deinit {
        encryptionKey.withUnsafeMutableBytes { if let b = $0.baseAddress { memset_s(b, $0.count, 0, $0.count) } }
        authenticationKey.withUnsafeMutableBytes { if let b = $0.baseAddress { memset_s(b, $0.count, 0, $0.count) } }
    }

    static func derive(password: [UInt8], salt: [UInt8], strength: AESStrength) throws -> AESKeys {
        guard !password.isEmpty else { throw ZipError.unsupported("empty password") }
        let n = strength.keyLength
        var out = [UInt8](repeating: 0, count: 2 * n + 2)
        let status = password.withUnsafeBufferPointer { pw in
            pw.withMemoryRebound(to: CChar.self) { pwc in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pwc.baseAddress, pwc.count,
                                     salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                                     WinZipAESScheme.iterations, &out, out.count)
            }
        }
        guard status == kCCSuccess else { throw ZipError.unsupported("PBKDF2 failed (\(status))") }
        defer { out.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) } }
        return AESKeys(encryptionKey: Array(out[0..<n]),
                       authenticationKey: Array(out[n..<(2 * n)]),
                       verifier: Array(out[(2 * n)...]))
    }
}

/// AES-CTR, little-endian 카운터(1부터). 암호화·복호화가 같은 연산이다.
final class WinZipCTR {
    private var cryptor: CCCryptorRef?
    private var counter = [UInt8](repeating: 0, count: 16)
    private var leftover = [UInt8]()   // 마지막 블록에서 남은 키스트림

    init(key: [UInt8]) throws {
        let status = CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                                     CCOptions(kCCOptionECBMode), key, key.count, nil, &cryptor)
        guard status == kCCSuccess, cryptor != nil else { throw ZipError.unsupported("AES init failed (\(status))") }
    }

    deinit { if let cryptor { CCCryptorRelease(cryptor) } }

    func apply(_ input: [UInt8]) throws -> [UInt8] {
        var out = input
        var i = 0
        while i < out.count && !leftover.isEmpty {
            out[i] ^= leftover.removeFirst()
            i += 1
        }
        let remaining = out.count - i
        guard remaining > 0 else { return out }

        let blocks = (remaining + 15) / 16
        var counters = [UInt8](repeating: 0, count: blocks * 16)
        for b in 0..<blocks {
            for k in 0..<16 {   // little-endian 증가
                counter[k] &+= 1
                if counter[k] != 0 { break }
            }
            counters.replaceSubrange((b * 16)..<(b * 16 + 16), with: counter)
        }
        var stream = [UInt8](repeating: 0, count: counters.count)
        var moved = 0
        let status = CCCryptorUpdate(cryptor, counters, counters.count, &stream, stream.count, &moved)
        guard status == kCCSuccess, moved == stream.count else { throw ZipError.unsupported("AES failed (\(status))") }

        for j in 0..<remaining { out[i + j] ^= stream[j] }
        if remaining % 16 != 0 { leftover = Array(stream[remaining...]) }
        return out
    }
}

final class HMACSHA1 {
    private var context = CCHmacContext()

    init(key: [UInt8]) {
        CCHmacInit(&context, CCHmacAlgorithm(kCCHmacAlgSHA1), key, key.count)
    }

    func update(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        CCHmacUpdate(&context, bytes, bytes.count)
    }

    func final() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CCHmacFinal(&context, &out)
        return out
    }
}

final class AESEntryDecryptor: EntryDecryptor {
    private let ctr: WinZipCTR
    private let hmac: HMACSHA1
    private let checksCRC: Bool

    init(keys: AESKeys, checksCRC: Bool) throws {
        ctr = try WinZipCTR(key: keys.encryptionKey)
        hmac = HMACSHA1(key: keys.authenticationKey)
        self.checksCRC = checksCRC
    }

    func process(_ input: [UInt8]) throws -> [UInt8] {
        hmac.update(input)   // HMAC 은 암호문에 대해 계산한다
        return try ctr.apply(input)
    }

    func finish() throws -> [UInt8] { [] }

    func verify(trailer: [UInt8]) throws {
        let mac = Array(hmac.final().prefix(WinZipAESScheme.authenticationCodeLength))
        guard constantTimeEqual(mac, trailer) else {
            throw ZipError.corrupted(entry: nil, reason: "authentication failed")
        }
    }

    var providesIntegrity: Bool { !checksCRC }
}

final class AESEntryEncryptor: EntryEncryptor {
    private let ctr: WinZipCTR
    private let hmac: HMACSHA1
    private let salt: [UInt8]
    private let verifier: [UInt8]
    let headerAdjustment: HeaderAdjustment

    init(keys: AESKeys, salt: [UInt8], strength: AESStrength, actualMethodID: UInt16) throws {
        ctr = try WinZipCTR(key: keys.encryptionKey)
        hmac = HMACSHA1(key: keys.authenticationKey)
        self.salt = salt
        verifier = keys.verifier

        var w = ByteWriter()
        w.u16(2)                 // AE-2
        w.append([0x41, 0x45])   // "AE"
        w.u8(strength.code)
        w.u16(actualMethodID)
        headerAdjustment = HeaderAdjustment(
            compressionMethodIDOverride: WinZipAESScheme.methodID,
            extraFields: [ExtraField(id: ExtraFieldID.winZipAES, data: w.bytes)],
            storesCRC: false,
            versionNeededToExtract: 51,
            generalPurposeFlags: GeneralPurposeFlag.encrypted)
    }

    func prefix() -> [UInt8] { salt + verifier }

    func process(_ input: [UInt8]) throws -> [UInt8] {
        let out = try ctr.apply(input)
        hmac.update(out)
        return out
    }

    func finish() throws -> [UInt8] { [] }

    func trailer() throws -> [UInt8] {
        Array(hmac.final().prefix(WinZipAESScheme.authenticationCodeLength))
    }
}
