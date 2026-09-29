import Foundation

// MARK: - 파이프라인 한 단계

/// 조각 단위 변환. 압축 · 해제 · 암호화 · 복호화가 모두 이 프로토콜이다.
public protocol ByteTransform: AnyObject {
    /// 입력 조각을 받아 출력 조각을 돌려준다. 빈 배열을 돌려줘도 된다(내부 버퍼링).
    func process(_ input: [UInt8]) throws -> [UInt8]
    /// 남은 출력을 전부 내보낸다. 한 번만 불린다.
    func finish() throws -> [UInt8]
}

// MARK: - 압축 코덱

public protocol CompressionCodec: Sendable {
    /// zip 규격의 압축 방식 번호 (저장 0, DEFLATE 8 …).
    var methodID: UInt16 { get }
    var versionNeededToExtract: UInt16 { get }
    func makeCompressor() throws -> any ByteTransform
    func makeDecompressor() throws -> any ByteTransform
}

// MARK: - 암호화 스킴

public struct EncryptionIdentifier: Hashable, Sendable, RawRepresentable, CustomStringConvertible {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let winZipAES = EncryptionIdentifier(rawValue: "winzip-aes")

    public var description: String { rawValue }
}

/// 목차에서 읽은 항목 헤더 (크기·오프셋은 Zip64 반영 후 값).
public struct EntryHeader: Sendable, Hashable {
    public let versionMadeBy: UInt16
    public let versionNeededToExtract: UInt16
    public let generalPurposeFlags: UInt16
    /// 헤더에 적힌 그대로의 압축 방식 번호 (AES 항목은 99).
    public let compressionMethodID: UInt16
    public let dosTime: UInt16
    public let dosDate: UInt16
    public let crc32: UInt32
    public let compressedSize: UInt64
    public let uncompressedSize: UInt64
    public let rawName: [UInt8]
    public let extraFields: [ExtraField]
    public let rawComment: [UInt8]
    public let diskNumberStart: UInt32
    public let internalAttributes: UInt16
    public let externalAttributes: UInt32
    public let localHeaderOffset: UInt64
    public let usesZip64: Bool

    public var isEncrypted: Bool { generalPurposeFlags & GeneralPurposeFlag.encrypted != 0 }
    public var usesDataDescriptor: Bool { generalPurposeFlags & GeneralPurposeFlag.dataDescriptor != 0 }

    public func extraField(_ id: UInt16) -> ExtraField? { extraFields.first { $0.id == id } }
}

public struct EncryptionContext: Sendable {
    /// 실제 압축 방식 번호.
    public let compressionMethodID: UInt16
    /// `requiresCRCBeforeEncryption` 인 스킴에만 채워진다.
    public let crc32: UInt32?
    public let dosModificationTime: UInt16
    public let uncompressedSize: UInt64
}

/// 암호화기가 헤더에 반영할 값.
public struct HeaderAdjustment: Sendable {
    /// 헤더의 압축 방식 번호를 덮어쓴다 (AES: 99). nil 이면 실제 방식 그대로.
    public var compressionMethodIDOverride: UInt16?
    public var extraFields: [ExtraField]
    /// false 면 CRC 필드를 0 으로 둔다 (AE-2).
    public var storesCRC: Bool
    public var versionNeededToExtract: UInt16
    /// 헤더 플래그에 OR 할 비트. 암호화 비트(bit 0)는 스킴이 켠다.
    public var generalPurposeFlags: UInt16

    public init(compressionMethodIDOverride: UInt16? = nil, extraFields: [ExtraField] = [],
                storesCRC: Bool = true, versionNeededToExtract: UInt16 = 20,
                generalPurposeFlags: UInt16 = 0x0001) {
        self.compressionMethodIDOverride = compressionMethodIDOverride
        self.extraFields = extraFields
        self.storesCRC = storesCRC
        self.versionNeededToExtract = versionNeededToExtract
        self.generalPurposeFlags = generalPurposeFlags
    }
}

public enum DecryptorResult {
    case wrongPassword
    case ready(any EntryDecryptor)
}

public protocol EntryDecryptor: ByteTransform {
    /// 암호문을 다 처리한 뒤 trailer 로 무결성을 검증한다. 실패하면 throw.
    func verify(trailer: [UInt8]) throws
    /// true 면 스킴이 무결성을 보장하므로 CRC 검사를 건너뛴다 (AE-2).
    var providesIntegrity: Bool { get }
    /// true 면 무결성 실패를 "비밀번호 틀림"으로 본다 — 무결성 수단이 CRC 뿐이라 틀린 비밀번호와 손상을 구분할 수 없는 스킴용.
    var integrityFailureIndicatesWrongPassword: Bool { get }
}

extension EntryDecryptor {
    public var integrityFailureIndicatesWrongPassword: Bool { false }
}

public protocol EntryEncryptor: ByteTransform {
    var headerAdjustment: HeaderAdjustment { get }
    /// 데이터 앞에 쓸 바이트.
    func prefix() -> [UInt8]
    /// `finish()` 뒤에 쓸 바이트 (AES: 인증 코드 10바이트).
    func trailer() throws -> [UInt8]
}

public protocol EncryptionScheme: Sendable {
    var identifier: EncryptionIdentifier { get }

    // 읽기
    /// 이 항목이 이 스킴으로 암호화됐는지 헤더로 판정한다.
    func matches(_ header: EntryHeader) -> Bool
    /// 실제 압축 방식 번호 (AES 는 extra field 에 들어 있다).
    func actualCompressionMethodID(for header: EntryHeader) -> UInt16
    /// 헤더의 CRC 필드가 의미 있는 값인가 (AE-2 는 0 을 저장한다 → false).
    func storesCRC(for header: EntryHeader) -> Bool
    /// 데이터 맨 앞에서 읽어야 할 바이트 수.
    func prefixLength(for header: EntryHeader) -> Int
    /// 데이터 맨 뒤 바이트 수.
    func trailerLength(for header: EntryHeader) -> Int
    /// 비밀번호를 빠르게 확인하고, 맞으면 복호화기를 만든다.
    func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult

    // 쓰기
    /// 암호화 전에 원문 CRC 가 필요한가 (헤더에 CRC 기반 확인값을 쓰는 스킴). true 면 원본을 한 번 더 읽는다.
    var requiresCRCBeforeEncryption: Bool { get }
    func makeEncryptor(password: [UInt8], context: EncryptionContext) throws -> any EntryEncryptor
}

extension EncryptionScheme {
    public func actualCompressionMethodID(for header: EntryHeader) -> UInt16 { header.compressionMethodID }
    public func storesCRC(for header: EntryHeader) -> Bool { true }
}

// MARK: - 저장소

/// 임의 위치 읽기. 여러 스레드에서 동시에 불려도 안전해야 한다.
public protocol ArchiveReadable: Sendable {
    func size() throws -> UInt64
    /// 요청보다 적게 돌려주면 끝에 닿은 것으로 본다.
    func read(at offset: UInt64, count: Int) throws -> [UInt8]
}

/// 순차 쓰기 + 헤더 보정용 덮어쓰기. 한 스레드에서만 쓴다.
public protocol ArchiveWritable: AnyObject {
    var position: UInt64 { get }
    func write(_ bytes: [UInt8]) throws
    func write(_ bytes: [UInt8], at offset: UInt64) throws
    /// offset 뒤를 버리고 position 을 offset 으로 되돌린다 (저장 방식으로 다시 쓰기 · 실패한 항목 되돌리기).
    func truncate(to offset: UInt64) throws
    /// 성공 확정 (파일: 임시 파일 → 최종 경로).
    func commit() throws
    /// 실패 시 정리.
    func discard()
}

// MARK: - 등록소

/// 압축 코덱과 암호화 스킴 모음. 값 타입이라 전역 상태를 바꾸지 않고 옵션으로 넘긴다.
public struct ZipRegistry: Sendable {
    public private(set) var codecs: [any CompressionCodec]
    public private(set) var schemes: [any EncryptionScheme]

    public init(codecs: [any CompressionCodec], schemes: [any EncryptionScheme]) {
        self.codecs = codecs
        self.schemes = schemes
    }

    /// 저장 · DEFLATE · WinZip AES. (ZipCrypto 는 넣지 않는다 — 깨진 암호이고, 앱이 직접 구현한 암호화가 되어
    /// 수출 규정 판단을 흐린다. 필요하면 `EncryptionScheme` 으로 구현해 `registering(_:)` 한다.)
    public static let standard = ZipRegistry(
        codecs: [StoreCodec(), DeflateCodec()],
        schemes: [WinZipAESScheme()])

    /// 같은 `methodID` 가 있으면 교체한다.
    public func registering(_ codec: any CompressionCodec) -> ZipRegistry {
        var copy = self
        copy.codecs.removeAll { $0.methodID == codec.methodID }
        copy.codecs.append(codec)
        return copy
    }

    /// 같은 `identifier` 가 있으면 **그 자리에서** 교체하고, 새 identifier 는 **맨 앞에** 넣는다.
    /// 판정은 앞에서부터 `matches` 를 묻는다 — 먼저 등록된(넓게 맞을 수 있는) 스킴은 뒤에 남아
    /// 새 스킴을 가리지 않는다 (기존 스킴을 교체해도 순서는 그대로).
    public func registering(_ scheme: any EncryptionScheme) -> ZipRegistry {
        var copy = self
        if let i = copy.schemes.firstIndex(where: { $0.identifier == scheme.identifier }) {
            copy.schemes[i] = scheme
        } else {
            copy.schemes.insert(scheme, at: 0)
        }
        return copy
    }

    public func codec(for methodID: UInt16) -> (any CompressionCodec)? {
        codecs.first { $0.methodID == methodID }
    }

    public func scheme(for identifier: EncryptionIdentifier) -> (any EncryptionScheme)? {
        schemes.first { $0.identifier == identifier }
    }

    public func scheme(matching header: EntryHeader) -> (any EncryptionScheme)? {
        guard header.isEncrypted,
              header.generalPurposeFlags & GeneralPurposeFlag.strongEncryption == 0 else { return nil }
        return schemes.first { $0.matches(header) }
    }
}
