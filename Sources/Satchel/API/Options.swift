import Foundation

/// zip 을 열 때의 설정.
public struct ReadOptions: Sendable {
    /// 파일 이름 해석 방식. 기본은 자동 판정 (UTF-8 플래그 → 유니코드 경로 extra → UTF-8 → CP949 → CP437).
    public var filenameEncoding: FilenameEncoding = .automatic
    /// 목차 항목 수 상한 — 열 때 바로 검사한다.
    public var maxEntryCount: Int = 100_000
    public var registry: ZipRegistry = .standard

    public init() {}
}

/// 해제 설정.
public struct ExtractOptions: Sendable {
    /// 동기 API 에서 쓰는 비밀번호. async API 에서는 비밀번호 제공자보다 먼저 시도한다.
    public var password: Password?
    /// 같은 경로에 파일이 있으면 false: `destinationExists` / true: 교체. 폴더는 합친다.
    public var overwrite: Bool = false
    /// 허용할 암호화 방식. nil = 등록소(`ReadOptions.registry`)에 등록된 전부. 예: `[.winZipAES]` 로 ZipCrypto 거부.
    public var allowedEncryption: Set<EncryptionIdentifier>?
    public var limits: ExtractLimits = .default
    public var restoresModificationDate: Bool = true
    /// rwx 비트만 복원한다. setuid · setgid · sticky 는 항상 제거한다.
    public var restoresPermissions: Bool = true
    /// 해제한 바이트 수로 진행률을 갱신한다. `cancel()` 하면 `ZipError.cancelled`.
    public var progress: Progress?

    public init() {}
}

/// 해제 상한 — 크기 폭탄 방지.
public struct ExtractLimits: Sendable {
    public var maxTotalUncompressedSize: UInt64
    /// 항목별 `해제 크기 / 압축 크기` 상한.
    public var maxCompressionRatio: UInt64

    public init(maxTotalUncompressedSize: UInt64 = 8 << 30, maxCompressionRatio: UInt64 = 1_000) {
        self.maxTotalUncompressedSize = maxTotalUncompressedSize
        self.maxCompressionRatio = maxCompressionRatio
    }

    public static let `default` = ExtractLimits()
    /// 메모리로 푸는 API(`ArchiveReader.data(for:)`)의 기본값 — 항목 하나 512 MiB.
    public static let inMemory = ExtractLimits(maxTotalUncompressedSize: 512 << 20)
    /// 상한 없음 — 입력을 신뢰할 수 있을 때만 쓴다.
    public static let unlimited = ExtractLimits(maxTotalUncompressedSize: .max, maxCompressionRatio: .max)
}

/// 생성 설정.
public struct WriteOptions: Sendable {
    public var compression: CompressionMethod = .deflate
    public var encryption: EncryptionMethod = .none
    /// `encryption != .none` 이면 필수.
    public var password: Password?
    /// 기본 UTF-8. `.cp949` 는 이름을 CP949 로 쓰고 유니코드 경로 extra(0x7075)에 UTF-8 이름을 함께 넣는다.
    public var filenameEncoding: FilenameEncoding = .utf8
    /// macOS 의 NFD(한글 자모 분리) 이름을 NFC 로 바꾼다.
    public var normalizesFilenamesToNFC: Bool = true
    public var zip64: Zip64Mode = .automatic
    /// `addDirectory` 에서 `.` 으로 시작하는 파일·폴더를 넣을지.
    public var includesHiddenFiles: Bool = true
    public var comment: String?
    public var registry: ZipRegistry = .standard
    public var progress: Progress?

    public init() {}
}

/// 항목 하나에만 적용할 설정. nil 인 값은 `WriteOptions` 를 따른다.
public struct EntryOptions: Sendable {
    public var compression: CompressionMethod?
    public var encryption: EncryptionMethod?
    public var password: Password?

    public init(compression: CompressionMethod? = nil, encryption: EncryptionMethod? = nil, password: Password? = nil) {
        self.compression = compression
        self.encryption = encryption
        self.password = password
    }
}

public enum CompressionMethod: Sendable, Hashable {
    case store
    /// `Compression` 프레임워크의 raw DEFLATE. 압축 레벨은 조절할 수 없다(프레임워크 고정).
    case deflate
    /// 등록소(`ZipRegistry`)에서 코덱을 찾는다.
    case custom(methodID: UInt16)
}

public enum EncryptionMethod: Sendable, Hashable {
    case none
    /// WinZip AES (AE-2).
    case aes(AESStrength = .bits256)
    /// ⚠️ 전통 PKWARE 암호 — **깨진 방식**이다. 알려진 공격으로 비밀번호 없이 풀린다.
    /// 운영체제 기본 압축 도구로 열어야 하는 경우에만 쓴다.
    case legacyZipCrypto
    /// 등록소(`ZipRegistry`)에서 스킴을 찾는다.
    case custom(EncryptionIdentifier)
}

public enum AESStrength: Sendable, Hashable, CaseIterable {
    case bits128, bits192, bits256

    var keyLength: Int {
        switch self { case .bits128: 16; case .bits192: 24; case .bits256: 32 }
    }
    var saltLength: Int {
        switch self { case .bits128: 8; case .bits192: 12; case .bits256: 16 }
    }
    var code: UInt8 {
        switch self { case .bits128: 1; case .bits192: 2; case .bits256: 3 }
    }
    init?(code: UInt8) {
        switch code { case 1: self = .bits128; case 2: self = .bits192; case 3: self = .bits256; default: return nil }
    }
}

public enum Zip64Mode: Sendable, Hashable {
    /// 필요할 때만 (항목 4 GiB 이상, 오프셋 4 GiB 이상, 항목 65,535개 이상).
    case automatic
    /// 모든 항목과 끝 레코드에 Zip64.
    case always
    /// 쓰지 않는다 — 필요해지면 `ZipError.unsupported`.
    case never
}

public enum FilenameEncoding: Sendable, Hashable {
    /// 읽기 전용 자동 판정. 쓰기에서는 `.utf8` 과 같다.
    case automatic
    case utf8
    case cp949
    case cp437
    case custom(String.Encoding)
}
