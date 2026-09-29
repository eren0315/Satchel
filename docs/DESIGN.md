# Satchel 설계

> 가방(satchel)에 파일을 넣고, 꺼내고, 잠근다 — **순수 Swift zip 라이브러리.**
> 압축 · 해제 · 암호화(WinZip AES) · Zip64 · 한국어 인코딩(CP949)을 지원하고, 압축 방식과 암호화 방식을 **공개 프로토콜로 끼워 넣을 수 있다.**
> 외부 의존성 없음 — `Foundation` · `Compression` · `CommonCrypto` · `Security` 만 쓴다.

- 상태: **0.1.0 구현 완료 (태그 전)** — 이 문서가 설계의 단일 기준이다. 바뀌면 이 문서를 고치고 맨 아래 변경 이력에 남긴다.
- 버전: **0.1.0 부터 시작**. `1.0.0` 전까지는 마이너 버전(0.x → 0.y)에서 공개 API 가 바뀔 수 있다(SemVer 0.x 규칙). 쓰는 쪽은 `exact:` 로 고정하길 권한다.

---

## 1. 범위

### 1.1 지원

| 영역 | 해제(읽기) | 생성(쓰기) |
| --- | --- | --- |
| 압축 방식 | 저장(0) · DEFLATE(8) · 등록한 사용자 코덱 | 저장 · DEFLATE · 등록한 사용자 코덱 |
| 암호화 | WinZip AES 128/192/256 (AE-1·AE-2) · 등록한 사용자 스킴 | **AES-256 · AE-2 가 기본**, AES 128/192 선택 가능 |
| Zip64 | ✅ | ✅ 필요할 때 자동 / 항상 / 끔 |
| 파일 이름 인코딩 | UTF-8(bit 11) · 유니코드 경로 extra(0x7075) · **CP949** · CP437 — 자동 판정 또는 지정 | UTF-8(기본) · **CP949**(+0x7075 로 UTF-8 병기) |
| 비밀번호 인코딩 | UTF-8 · **CP949** · CP437 후보를 차례로 시도 | 지정한 인코딩 1개 (기본 UTF-8) |
| 비밀번호 전달 | 고정 비밀번호(동기) · **비밀번호 제공자**(async, 항목별 · 재시도 · 건너뛰기 · 취소) | 고정 비밀번호, 항목별 지정 가능 |
| 입출력 | 파일 · 메모리(`Data`) · 사용자 저장소 | 파일 · 메모리 · 사용자 저장소 |
| 부가 기능 | 항목 목록 · 항목 하나만 `Data` 로 · 비밀번호 검증만 · 진행률 · 취소 | 진행률 · 취소 |

### 1.2 지원하지 않음 — 만나면 `ZipError.unsupported` 로 명시적으로 실패

| 항목 | 이유 |
| --- | --- |
| **ZipCrypto (전통 PKWARE 암호)** — 읽기 · 쓰기 모두 | 깨진 암호(알려진 평문 공격으로 비밀번호 없이 풀린다). 라이브러리가 **직접 구현한 암호화**가 되어 쓰는 앱의 수출 규정(암호화) 판단을 흐린다. 목록에는 `zipcrypto` 로 보이고, 풀면 이유를 담아 실패한다. 필요하면 `EncryptionScheme` 으로 구현해 등록한다 (§5) |
| PKWARE Strong Encryption (플래그 bit 6) · 목차 암호화 (bit 13) | 독점 규격, 쓰이는 곳이 거의 없다 |
| 분할(멀티 디스크) zip | 필요성 낮음 |
| bzip2 · LZMA · deflate64 · zstd 등 | Apple 프레임워크로 처리할 수 없다 → **사용자 코덱으로 끼워 넣을 수 있게만** 한다 (§5) |
| 심볼릭 링크 항목 | 경로 탈출 수단. 읽기·쓰기 모두 거부 |
| 기존 zip 에 항목 추가·삭제 (in-place 수정) | 새로 만드는 것으로 대신한다 |
| UI | 라이브러리 밖. 비밀번호 입력 창은 **샘플 앱**에서만 보여 준다 |

### 1.3 원칙
1. **기본값은 안전한 쪽.** 생성 기본 암호화는 AES-256. 깨진 암호(ZipCrypto)는 넣지 않는다.
2. **외부에서 받은 zip 을 믿지 않는다.** 경로 탈출 · 심볼릭 링크 · 크기 폭탄 · 무결성 위반을 막는다 (§8).
3. **해제는 전부 되거나 아무것도 남지 않는다** (§9).
4. **비밀번호·키는 로그·에러·`description` 어디에도 나오지 않는다.**
5. **모르는 것을 조용히 넘기지 않는다.** 지원하지 않는 기능은 이유를 담아 실패한다.
6. **암호 알고리즘을 직접 구현하지 않는다.** AES · PBKDF2 · HMAC 은 모두 OS 의 `CommonCrypto` 를 호출한다(CTR 모드 조립만 우리 코드 — §11.1). 쓰는 앱이 "OS 의 표준 암호화만 쓴다"고 설명할 수 있게.

---

## 2. 패키지 구성

```
Satchel/
├── Package.swift                 // swift-tools-version 6.0 · Swift 6 언어 모드 · iOS 15 / macOS 12
├── LICENSE                       // 0BSD
├── README.md
├── docs/DESIGN.md                // 이 문서
├── Sources/Satchel/
│   ├── API/                      // Zip · ArchiveReader · ArchiveWriter · 옵션 · Entry · ZipError
│   ├── Password/                 // Password · PasswordProvider · 후보 인코딩
│   ├── Extension/                // 공개 확장 지점: CompressionCodec · EncryptionScheme · ByteTransform · 저장소 · ZipRegistry
│   ├── Format/                   // 로컬 헤더 · 목차 · EOCD · Zip64 EOCD/locator · extra field · DOS 시각
│   ├── Codecs/                   // StoreCodec · DeflateCodec (Compression 프레임워크)
│   ├── Encryption/               // WinZipAES
│   ├── Text/                     // 파일 이름·비밀번호 인코딩 (UTF-8 · CP949 · CP437) · NFC 정규화
│   ├── Safety/                   // 항목 경로 검증 · 상한 검사
│   ├── Storage/                  // 파일 · 메모리 저장소, 64 KiB 버퍼
│   ├── Engine/                   // 해제 세션(사전 점검 · 임시 폴더 · 원자적 이동) · 진행률/취소
│   └── Checksum/                 // CRC32
├── Tests/SatchelTests/           // 픽스처는 테스트 중에 시스템 도구로 만든다 (§12) — 바이너리를 커밋하지 않는다
└── Example/SatchelExample.swiftpm // 샘플 앱 (SwiftUI, Xcode 로 연다)
```

- **iOS 15 / macOS 12**: 쓰는 앱의 최소 지원 버전(iOS 15)에 맞춘다 — 패키지가 앱보다 높으면 연결이 안 된다. 기술적 하한은 iOS 13(async API 의 Swift Concurrency back-deploy)이지만, 15 로 두면 Concurrency 를 OS 내장 런타임으로 쓴다. macOS 12 는 iOS 15 와 같은 세대이고, `swift test` 를 시뮬레이터 없이 돌리기 위해 넣는다.
- **Swift 6 언어 모드**: 엄격한 동시성 검사로 스레드 안전을 컴파일러가 보장하게 한다. 쓰는 쪽은 Xcode 16 이상이어야 한다.
- **의존성 0개** (테스트 포함). 교차 검증은 macOS 기본 도구(`bsdtar`(libarchive) · `zip`/`unzip` · `ditto`)와 `python3`, 설치돼 있으면 `7zz` 로 한다 (§12).
- **공개 타입 이름을 모듈 이름 `Satchel` 과 같게 두지 않는다** — `Satchel.X` 로 한정할 때 모듈과 타입이 충돌한다.

---

## 3. 구조

```
┌ 공개 API ───────────────────────────────────────────────────────────┐
│  Zip (간편 함수)      ArchiveReader            ArchiveWriter          │
│  Password · PasswordProvider · WriteOptions · ExtractOptions · Entry  │
└──────────────────────────────┬──────────────────────────────────────┘
┌ 항목 파이프라인 ───────────────┴──────────────────────────────────────┐
│  읽기: 저장소 → [복호화 + 무결성] → [해제 + CRC + 크기 상한] → 출력    │
│  쓰기: 원본 → [압축] → [암호화 + 무결성] → 저장소 (헤더는 되돌아가 보정) │
└──────────────────────────────┬──────────────────────────────────────┘
┌ 등록소 ZipRegistry ───────────┴──────────────────────────────────────┐
│  CompressionCodec: Store · Deflate · (사용자)                          │
│  EncryptionScheme: WinZipAES · (사용자)                                │
└──────────────────────────────┬──────────────────────────────────────┘
┌ 형식 · 텍스트 · 안전 ──────────┴──────────────────────────────────────┐
│  헤더/extra field 해석(Zip64 포함) · 이름 인코딩 · 경로 검증           │
└──────────────────────────────┬──────────────────────────────────────┘
┌ 저장소 ───────────────────────┴──────────────────────────────────────┐
│  ArchiveReadable / ArchiveWritable: 파일 · 메모리 · (사용자)           │
└─────────────────────────────────────────────────────────────────────┘
```

- 내부 크기·오프셋은 **전부 `UInt64`**. Zip64 여부는 헤더를 읽고 쓰는 층에서만 다룬다.
- 파이프라인 단계는 전부 `ByteTransform`(§5.1) 이다. 내장 코덱·스킴도 사용자 것과 **같은 프로토콜**로 구현한다 — 확장 지점이 실제로 쓸 만한지 내장 구현이 먼저 증명한다.

---

## 4. 공개 API

### 4.1 간편 함수

```swift
public enum Zip {
    /// items(파일·폴더)를 묶어 zip 을 만든다. 폴더는 하위 전체, 항목 이름은 각 item 의 부모 기준 상대 경로.
    @discardableResult
    public static func create(at archiveURL: URL, from items: [URL],
                              options: WriteOptions = .init()) throws -> CreateResult

    /// 고정 비밀번호(또는 없음)로 전부 푼다.
    @discardableResult
    public static func extract(_ archiveURL: URL, to destinationURL: URL,
                               readOptions: ReadOptions = .init(),
                               options: ExtractOptions = .init()) throws -> ExtractResult

    /// 비밀번호 제공자에게 항목마다 물어 가며 푼다. Task 취소를 따른다.
    @discardableResult
    public static func extract(_ archiveURL: URL, to destinationURL: URL,
                               readOptions: ReadOptions = .init(),
                               options: ExtractOptions = .init(),
                               passwordProvider: any PasswordProvider) async throws -> ExtractResult
}
```

### 4.2 Reader / Writer

```swift
public final class ArchiveReader: Sendable {
    public convenience init(url: URL, options: ReadOptions = .init()) throws
    public convenience init(data: Data, options: ReadOptions = .init()) throws
    public init(storage: any ArchiveReadable, options: ReadOptions = .init()) throws

    public var entries: [Entry] { get }                   // 목차 기준. 열 때 한 번 읽는다
    public var comment: String? { get }

    public func extract(_ entry: Entry, to url: URL, password: Password? = nil, limits: ExtractLimits = .default,
                        allowedEncryption: Set<EncryptionIdentifier>? = nil) throws
    public func data(for entry: Entry, password: Password? = nil, limits: ExtractLimits = .inMemory,
                     allowedEncryption: Set<EncryptionIdentifier>? = nil) throws -> Data
    public func verify(_ password: Password, for entry: Entry, thorough: Bool = false,
                       limits: ExtractLimits = .default) throws -> PasswordCheck
    // 항목 단위 API 도 전체 해제와 같은 구조 · 지원 · 상한 점검을 거친다 (겹침 · 이름 불일치 · 비율).
    public func extractAll(to url: URL, options: ExtractOptions) throws -> ExtractResult
    public func extractAll(to url: URL, options: ExtractOptions,
                           passwordProvider: any PasswordProvider) async throws -> ExtractResult
}

public final class ArchiveWriter {
    public convenience init(url: URL, options: WriteOptions = .init()) throws   // 이미 있으면 destinationExists
    public convenience init(options: WriteOptions = .init())                   // 메모리
    public init(storage: any ArchiveWritable, options: WriteOptions = .init())

    public func addFile(at url: URL, as path: String? = nil, options: EntryOptions? = nil) throws
    public func addDirectory(at url: URL, as path: String? = nil, options: EntryOptions? = nil) throws  // 하위 전체
    public func add(_ data: Data, as path: String, modificationDate: Date = Date(), options: EntryOptions? = nil) throws
    public func addEmptyDirectory(as path: String, modificationDate: Date = Date()) throws

    @discardableResult
    public func finish() throws -> CreateResult   // 파일·사용자 저장소
    public func finishData() throws -> Data       // 메모리
}
```

- `ArchiveWriter` 는 순서대로 쓰는 객체라 한 스레드에서만 쓴다 (`Sendable` 아님).
- `finish()` 를 부르지 않고 해제되면 임시 파일을 지우고 결과를 만들지 않는다.

### 4.3 옵션

```swift
public struct ReadOptions: Sendable {                 // zip 을 열 때
    public var filenameEncoding: FilenameEncoding = .automatic
    public var maxEntryCount: Int = 100_000           // 열 때 바로 검사
    public var registry: ZipRegistry = .standard
}

public struct WriteOptions: Sendable {                // ArchiveWriter · Zip.create
    public var compression: CompressionMethod = .deflate
    public var encryption: EncryptionMethod = .none
    public var password: Password? = nil              // encryption != .none 이면 필수
    public var filenameEncoding: FilenameEncoding = .utf8
    public var normalizesFilenamesToNFC: Bool = true  // macOS 의 NFD(자모 분리) 이름을 NFC 로
    public var zip64: Zip64Mode = .automatic
    public var includesHiddenFiles: Bool = true
    public var comment: String? = nil
    public var registry: ZipRegistry = .standard
    public var progress: Progress? = nil
}

public struct EntryOptions: Sendable {                // 항목 단위 덮어쓰기 (nil 인 값은 WriteOptions 를 따른다)
    public var compression: CompressionMethod?
    public var encryption: EncryptionMethod?
    public var password: Password?
}

public struct ExtractOptions: Sendable {
    public var password: Password? = nil              // 동기 API 용 · async 에서는 제공자보다 먼저 시도
    public var overwrite: Bool = false                // 폴더는 합치고, 같은 경로 파일은 false: destinationExists / true: 교체
    public var allowedEncryption: Set<EncryptionIdentifier>? = nil   // nil = 등록소에 등록된 전부
    public var limits: ExtractLimits = .default
    public var restoresModificationDate: Bool = true
    public var restoresPermissions: Bool = true       // rwx 만. setuid/setgid/sticky 는 항상 제거
    public var progress: Progress? = nil
}

public struct ExtractLimits: Sendable {
    public var maxTotalUncompressedSize: UInt64 = 8 << 30   // 8 GiB
    public var maxCompressionRatio: UInt64 = 1_000          // 항목별 해제/압축 비율 상한 (DEFLATE 최대치 ≈ 1032)
    public static let `default`: ExtractLimits
    public static let inMemory: ExtractLimits               // data(for:) 기본값 — 항목 하나 512 MiB
    public static let unlimited: ExtractLimits              // 입력을 신뢰할 수 있을 때만
}

public enum CompressionMethod: Sendable, Hashable { case store, deflate, custom(methodID: UInt16) }
public enum EncryptionMethod: Sendable, Hashable {
    case none
    case aes(AESStrength = .bits256)
    case custom(EncryptionIdentifier)
}
public enum AESStrength: Sendable, CaseIterable { case bits128, bits192, bits256 }
public enum Zip64Mode: Sendable { case automatic, always, never }
public enum FilenameEncoding: Sendable, Hashable {
    case automatic                                    // 읽기: §7.1 순서로 판정 / 쓰기: utf8 과 같다
    case utf8, cp949, cp437
    case custom(String.Encoding)
}
```

- DEFLATE 압축 **레벨은 옵션이 없다** — `Compression` 프레임워크가 레벨 조절을 지원하지 않는다(고정). 레벨이 필요하면 사용자 코덱으로 대체한다.

### 4.4 Entry · 결과

```swift
public struct Entry: Sendable, Hashable {
    public let path: String                           // 디코딩 · 정규화된 이름 ('/' 구분)
    public let rawPath: [UInt8]                       // 원본 바이트
    public let kind: Kind                             // .file / .directory / .symlink (symlink 는 해제 시 거부)
    public let uncompressedSize: UInt64
    public let compressedSize: UInt64
    public let crc32: UInt32?                         // AE-2 는 nil
    public let modificationDate: Date?
    public let compressionMethodID: UInt16
    public let encryption: EncryptionIdentifier?      // nil = 암호화 안 됨
    public let isZip64: Bool
    public let unixPermissions: UInt16?
    public let extraFields: [ExtraField]              // 원본 extra field (id + 데이터) 그대로
}

public struct ExtractResult: Sendable {
    public let extracted: [Entry]
    public let skipped: [Entry]                       // 비밀번호 제공자가 .skipEntry 로 건너뛴 항목
}
public struct CreateResult: Sendable {
    public let entries: [Entry]
    public let usedZip64: Bool
}
```

### 4.5 에러

```swift
public enum ZipError: Error, Sendable, Equatable {
    case passwordRequired(entry: String)
    case wrongPassword(entry: String)
    case corrupted(entry: String?, reason: String)     // 구조 손상 · CRC · HMAC · 선언 크기 초과
    case unsafeEntryPath(String, reason: String)       // 경로 탈출 · 절대 경로 · 중복 · 심볼릭 링크
    case limitExceeded(String)
    case unsupported(String)                           // §1.2
    case disallowedEncryption(EncryptionIdentifier)    // ExtractOptions.allowedEncryption 밖
    case destinationExists(String)
    case filenameEncodingFailed(String)                // 지정 인코딩으로 표현할 수 없는 이름
    case cancelled
}
```

- 파일 입출력 에러(`CocoaError` 등)는 **감싸지 않고 그대로** 던진다.
- 에러 문자열에는 항목 이름과 이유만. **비밀번호·키·복호화된 내용은 절대 넣지 않는다.**

---

## 5. 공개 확장 지점

> 0.x 동안은 이 시그니처도 마이너 버전에서 바뀔 수 있다. 내장 구현(Store · Deflate · WinZipAES)이 모두 이 프로토콜로 만들어진다.

### 5.1 ByteTransform — 파이프라인 한 단계

```swift
public protocol ByteTransform: AnyObject {
    /// 입력 조각을 받아 출력 조각을 돌려준다. 빈 배열을 돌려줘도 된다(내부에 버퍼링).
    func process(_ input: [UInt8]) throws -> [UInt8]
    /// 남은 출력을 전부 내보낸다. 한 번만 불린다.
    func finish() throws -> [UInt8]
}
```

### 5.2 CompressionCodec

```swift
public protocol CompressionCodec: Sendable {
    var methodID: UInt16 { get }                      // zip 규격의 압축 방식 번호
    var versionNeededToExtract: UInt16 { get }
    func makeCompressor() throws -> any ByteTransform
    func makeDecompressor() throws -> any ByteTransform
}
```

### 5.3 EncryptionScheme

```swift
public struct EncryptionIdentifier: Hashable, Sendable, RawRepresentable {
    public let rawValue: String
    public static let winZipAES = EncryptionIdentifier(rawValue: "winzip-aes")
}

public protocol EncryptionScheme: Sendable {
    var identifier: EncryptionIdentifier { get }

    // ── 읽기 ──
    /// 이 항목이 이 스킴으로 암호화됐는지 헤더(플래그 · 압축 방식 ID · extra field)로 판정
    func matches(_ header: EntryHeader) -> Bool
    /// 실제 압축 방식 번호 (AES 는 extra field 안에 있다). 기본 구현 = 헤더 값
    func actualCompressionMethodID(for header: EntryHeader) -> UInt16
    /// 헤더의 CRC 필드가 의미 있는 값인가 (AE-2 → false). `Entry.crc32` 가 nil 이 되는 근거. 기본 구현 = true
    func storesCRC(for header: EntryHeader) -> Bool
    /// 데이터 맨 앞에서 읽어야 할 바이트 수 (AES: salt + 확인값)
    func prefixLength(for header: EntryHeader) -> Int
    /// 맨 뒤 바이트 수 (AES: 인증 코드 10)
    func trailerLength(for header: EntryHeader) -> Int
    /// 비밀번호를 빠르게 확인하고, 맞으면 복호화기를 만든다
    func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult

    // ── 쓰기 ──
    /// 암호화하기 전에 원문 CRC 가 필요한가 (헤더에 CRC 기반 확인값을 쓰는 스킴 — 원본을 한 번 더 읽는다)
    var requiresCRCBeforeEncryption: Bool { get }
    func makeEncryptor(password: [UInt8], context: EncryptionContext) throws -> any EntryEncryptor
}

public enum DecryptorResult {
    case wrongPassword
    case ready(any EntryDecryptor)
}

public protocol EntryDecryptor: ByteTransform {
    /// 암호문을 다 읽은 뒤 trailer 로 무결성을 검증한다 (실패 시 throw)
    func verify(trailer: [UInt8]) throws
    /// true 면 스킴이 무결성을 보장하므로 CRC 가 0 이어도 된다 (AE-2)
    var providesIntegrity: Bool { get }
    /// true 면 무결성 실패를 "비밀번호 틀림"으로 본다 (무결성 수단이 CRC 뿐인 스킴). 기본 구현 = false
    var integrityFailureIndicatesWrongPassword: Bool { get }
}

public protocol EntryEncryptor: ByteTransform {
    var headerAdjustment: HeaderAdjustment { get }    // 압축 방식 ID 덮어쓰기(AES=99) · 플래그 · extra field · CRC 저장 여부 · version needed
    func prefix() -> [UInt8]                          // 데이터 앞에 쓸 바이트
    func trailer() throws -> [UInt8]                  // finish() 뒤에 쓸 바이트 (AES: HMAC 10)
}

public struct EncryptionContext: Sendable {
    public let compressionMethodID: UInt16
    public let crc32: UInt32?                         // requiresCRCBeforeEncryption 일 때만 채워진다
    public let dosModificationTime: UInt16
    public let uncompressedSize: UInt64
}
```

### 5.4 저장소

```swift
public protocol ArchiveReadable: Sendable {
    func size() throws -> UInt64
    func read(at offset: UInt64, count: Int) throws -> [UInt8]   // 여러 스레드에서 동시에 불려도 안전해야 한다. 덜 돌려주면 끝
}

public protocol ArchiveWritable: AnyObject {
    var position: UInt64 { get }
    func write(_ bytes: [UInt8]) throws
    func write(_ bytes: [UInt8], at offset: UInt64) throws        // 헤더 보정용 (되돌아가 덮어쓰기)
    func truncate(to offset: UInt64) throws                       // 저장 방식으로 다시 쓰기 · 실패한 항목 되돌리기
    func commit() throws                                          // 성공 확정 (파일: 임시 → 최종 이동)
    func discard()                                                // 실패 시 정리
}
```

- 내장 구현(공개): `FileReadStorage`(`pread`) · `MemoryReadStorage` · `FileWriteStorage`(임시 파일 → `renamex_np(RENAME_EXCL)`) · `MemoryWriteStorage`.

### 5.5 등록소

```swift
public struct ZipRegistry: Sendable {
    public static let standard: ZipRegistry           // Store · Deflate · WinZipAES
    public init(codecs: [any CompressionCodec], schemes: [any EncryptionScheme])
    public func registering(_ codec: any CompressionCodec) -> ZipRegistry     // 같은 methodID 면 교체
    public func registering(_ scheme: any EncryptionScheme) -> ZipRegistry    // 같은 identifier 면 교체
}
```

- 등록소는 **값 타입**이다. 전역 상태를 바꾸지 않고 옵션으로 넘긴다 — 한 앱 안에서 서로 다른 설정이 섞여도 안전하다.
- 암호화 판정은 스킴을 순서대로 `matches` 에 물어 **첫 번째로 맞는 것**을 쓴다. `registering(_:)` 은 **새 identifier 를 맨 앞에** 넣고, **같은 identifier 는 그 자리에서** 교체한다 — 먼저 등록된(넓게 맞을 수 있는) 스킴은 뒤에 남아 새 스킴을 가리지 않는다(기존 스킴을 교체해도 순서 유지).
- **쓰기도 등록소를 거친다** — `.aes` 도 등록소에서 identifier 로 찾는다. 등록소에서 뺀 방식은 쓸 수 없고, 교체한 구현이 쓰인다(내장 AES 만 호출마다 강도를 받는다). 저장 방식 대체도 등록소의 저장 코덱을 쓴다. 아무것도 안 맞는데 플래그 bit 0 이 켜져 있으면 `unsupported`.
- 내장 코덱·스킴도 공개 타입이다: `StoreCodec` · `DeflateCodec` · `WinZipAESScheme(strength:)`.

---

## 6. 비밀번호 체계

### 6.1 Password

```swift
public struct Password: Sendable, CustomStringConvertible {
    /// 문자열 비밀번호. 해제할 때는 encodings 순서로 바이트 후보를 만들어 차례로 시도한다.
    public init(_ string: String, encodings: [PasswordEncoding] = [.utf8, .cp949, .cp437])
    /// 바이트 그대로 (Keychain 등에서 꺼낸 키)
    public init(bytes: [UInt8])

    public var description: String { "Password(•••)" }   // 절대 내용을 드러내지 않는다
}
public enum PasswordEncoding: Sendable { case utf8, cp949, cp437, custom(String.Encoding) }
```

- **해제**: 인코딩마다 **NFC · NFD 두 형태**로 후보 바이트열을 만든 뒤 같은 것은 합친다(ASCII 비밀번호는 모두 같다). 표현할 수 없는 인코딩(예: 한글 → CP437)은 건너뛴다. NFD 후보가 있는 이유: macOS `Process` 등은 인수를 NFD 로 넘겨, 다른 도구가 NFD 바이트로 암호화했을 수 있다(테스트로 확인).
- **생성**: `encodings` 의 **첫 번째**로, **NFC** 형태를 쓴다. AES 의 기본은 UTF-8.
- 메모리: 내부 저장소를 참조 타입 하나로 두고, 해제될 때 0 으로 덮는다(최선의 노력 — Swift `String` 원본은 지울 수 없으므로 민감하면 `bytes:` 를 쓴다).

### 6.2 비밀번호 제공자

```swift
public protocol PasswordProvider: Sendable {
    func password(for request: PasswordRequest) async -> PasswordResponse
}

public struct PasswordRequest: Sendable {
    public let entry: Entry
    public let attempt: Int                           // 1부터. 틀리면 올라간다
    public let reason: Reason                         // .required(처음) / .wrongPassword(직전 것이 틀림)
}

/// 클로저로 만드는 제공자: ClosurePasswordProvider { request in ... }
public enum PasswordResponse: Sendable {
    case password(Password)
    case passwords([Password])                        // 여러 개를 차례로 시도
    case skipEntry                                    // 이 항목만 빼고 계속
    case cancel                                       // 전체 중단 → ZipError.cancelled
}
```

- **맞은 비밀번호는 기억한다.** 다음 암호화 항목에서는 먼저 **이미 맞았던 비밀번호로** 시도하고, 틀릴 때만 제공자에게 묻는다. 한 비밀번호로 잠긴 zip 이면 한 번만 묻는다.
- **묻는 시점**: 사전 점검(§9-1)이 끝난 뒤, 그 항목을 풀기 직전. 사전 점검에서 걸리는 zip 은 비밀번호를 묻기 전에 실패한다.
- 제공자는 **메인 액터가 아닌 곳에서** 불린다. UI 를 띄우는 제공자는 스스로 `@MainActor` 로 넘어간다(샘플 앱 참고).
- 동기 API 는 `ExtractOptions.password` 하나를 쓴다. 필요한데 없으면 `passwordRequired`, 틀리면 `wrongPassword`.

### 6.3 비밀번호 판정

| 스킴 | 빠른 확인 | 확인 통과 후 실패 | 보고 |
| --- | --- | --- | --- |
| WinZip AES | 확인값 2바이트 (틀린 비밀번호가 통과할 확률 1/65,536) | HMAC 불일치 | 확인값 불일치 → `wrongPassword` / HMAC 불일치 → `corrupted` |
| 사용자 스킴 (`integrityFailureIndicatesWrongPassword = true`) | 스킴이 정한다 | CRC 불일치 | 둘 다 → **`wrongPassword`** (무결성 수단이 CRC 뿐이라 틀린 비밀번호와 손상을 구분할 수 없는 스킴용) |
- 후보(인코딩 · `passwords`)를 시도할 때 **확인값을 통과한 후보만** 복호화까지 간다. 통과한 후보가 CRC/HMAC 에서 실패하면 다음 후보로 넘어간다.

### 6.4 `verify(_:for:)`
- 풀지 않고 비밀번호가 맞는지만 본다.
- `PasswordCheck`: `.correct`(무결성까지 확인) / `.likelyCorrect`(빠른 확인만 통과 — 기본) / `.wrong`. 암호화되지 않은 항목은 `.correct`.
- `thorough: true` 를 주면 항목 전체를 복호화해 무결성까지 검증한다(비용 = 해제와 같음, 쓰기 없음). AES 는 확인값 통과 후 HMAC 이 틀리면 `corrupted` 를 던진다.

---

## 7. 텍스트 인코딩

### 7.1 파일 이름 — 읽기 (`.automatic`)
1. 플래그 **bit 11** → UTF-8
2. **0x7075 유니코드 경로 extra field** 가 있고, 그 안의 CRC 가 원본 이름 바이트의 CRC 와 같으면 → 그 UTF-8 이름 (다르면 무시 — 이름을 바꾼 뒤 extra 를 안 고친 도구가 있다)
3. 원본 바이트가 **올바른 UTF-8** → UTF-8 (bit 11 없이 UTF-8 을 쓰는 도구가 많다)
4. **CP949** 로 디코딩되면 → CP949 (한국 Windows 도구)
5. 그 밖 → **CP437** (항상 디코딩된다 — 256개 바이트 전부 대응)

- 순서 4→5 는 **한국어 환경 기준**이다. 서유럽 CP437 이름이 우연히 CP949 로도 해석되면 잘못 읽힐 수 있다 → 그런 환경은 `filenameEncoding: .cp437` 로 강제한다.
- CP949 · CP437 변환은 `CFStringConvertEncodingToNSStringEncoding`(`dosKorean` · `dosLatinUS`)을 쓴다.

### 7.2 파일 이름 — 쓰기
- **`.utf8`(기본)**: bit 11 켬.
- **`.cp949`**: bit 11 끔, 이름을 CP949 로 쓰고 **0x7075 에 UTF-8 이름을 함께 넣는다** — 옛 도구는 CP949 로, 요즘 도구는 UTF-8 로 읽는다. CP949 로 표현할 수 없는 문자가 있으면 `filenameEncodingFailed`.
- **NFC 정규화(기본 켬)**: macOS 에서 온 이름은 NFD(한글 자모 분리)일 수 있다. 그대로 쓰면 Windows 에서 글자가 깨져 보인다.

### 7.3 비밀번호
- §6.1. 읽기는 후보를 차례로, 쓰기는 첫 번째 인코딩 하나.
- CP949 비밀번호로 만든 zip 은 **Satchel · 한국어 Windows 도구와만** 호환이 보장된다. README 에 적는다.

---

## 8. 안전

### 8.1 항목 경로 (해제 시 모든 항목, 사전 점검에서 전부)

| 규칙 | 처리 |
| --- | --- |
| `\` | `/` 로 바꾼 뒤 검사 |
| 빈 이름 · NUL · 제어 문자 | `unsafeEntryPath` |
| `/` 로 시작 · `C:` 같은 드라이브 문자 · `//서버` | `unsafeEntryPath` |
| 구성 요소에 `..` | `unsafeEntryPath` (안쪽으로 되돌아오는 경우도 거부 — 단순하게) |
| 구성 요소 `.` · 연속 `/` | 제거해서 정규화 |
| 최종 경로가 해제 폴더 안인지 | `standardizedFileURL` 로 다시 확인 (위 규칙의 안전망) |
| 중복 이름 — **NFC 정규화 + 대소문자 무시** 비교 | `unsafeEntryPath` (macOS 기본 볼륨은 대소문자·정규화를 구분하지 않아 덮어쓰기가 된다) |
| 구성 요소 256개 초과 · 4,096 바이트 초과 | `unsafeEntryPath` (`path too deep` / `path too long`) |
| 파일 `a` 와 폴더 `a/`(또는 `a/b`) 가 함께 있음 | `unsafeEntryPath` |

중복 · 파일/폴더 충돌은 **경로 트리**(구성 요소 단위, `PathTree`)로 판정한다 — 비용이 경로 길이에 비례한다. 상위 경로 문자열을 전부 만들어 집합에 넣으면 깊은 경로 하나로 깊이의 제곱만큼 메모리를 쓴다(리뷰에서 발견).
| 심볼릭 링크 (Unix 모드 `S_IFLNK`) | `unsafeEntryPath` |
| 로컬 헤더 이름 ≠ 목차 이름 | `corrupted` (도구마다 다르게 풀리는 zip 을 막는다) |

### 8.2 크기 폭탄
- 사전 점검: 항목 수 ≤ `maxEntryCount`, 선언 해제 크기 합 ≤ `maxTotalUncompressedSize`, 항목별 `해제 / 압축` ≤ `maxCompressionRatio` (압축 크기 0 인 빈 파일은 제외).
- 해제 중: **실제로 나온 바이트가 선언 크기를 넘는 순간 중단** → `corrupted`. 선언 크기를 속인 zip 을 막는다. 해제기에는 **8 KiB 씩** 넣는다 — 검사 전에 조각 하나가 부풀 수 있는 양(DEFLATE 최대 ≈ 1032배)을 약 8 MiB 로 묶는다.
- 메모리로 푸는 `data(for:)` 는 기본 상한이 `ExtractLimits.inMemory`(512 MiB)다.
- 겹치는 항목(두 목차 항목이 같은 데이터 영역을 가리킴 — "겹침 폭탄") → 데이터 영역 범위가 서로 겹치면 `corrupted`.

### 8.3 권한
- 복원하는 건 `rwx` 비트뿐이고 **group/other 쓰기는 제거**한다(`& 0o755` — 외부 zip 이 world-writable 을 강요하지 못하게). **setuid · setgid · sticky 는 항상 제거**한다.
- 소유자 접근은 보장한다 — 폴더 최소 `u+rwx`, 파일 최소 `u+rw`.
- 해제 파일은 `O_NOFOLLOW` 로 연다. 대상 폴더 안에 **이미 있는 심볼릭 링크**를 거쳐 들어가려는 항목은 `unsafeEntryPath` (링크를 따라 밖에 쓰는 것 방지).

---

## 9. 해제의 원자성

1. **사전 점검** — 목차를 끝까지 읽고 §8 규칙 · 상한 · 지원 여부(압축 방식 · 암호화 방식 · `allowedEncryption`) · 비밀번호 필요 여부(동기 API)를 **아무것도 쓰기 전에** 전부 검사한다.
2. `destinationURL` 의 **부모 폴더** 안에 `.satchel-<UUID>` 임시 폴더를 만든다 (같은 볼륨 → 이동이 원자적).
3. 항목마다 임시 폴더에 풀고 **CRC · HMAC 을 검증한 뒤** 다음 항목으로 간다.
4. 전부 성공하면:
   - `destinationURL` 이 없으면 → 임시 폴더를 **통째로 이름 변경** (원자적)
   - 있으면 → **옮기기 전에** 전부 검사한다: 대상 안의 기존 심볼릭 링크 → `unsafeEntryPath`, **파일 ↔ 폴더 충돌은 overwrite 여도** `destinationExists`(사용자 폴더 트리를 지우지 않는다), 파일 ↔ 파일 충돌은 `overwrite == false` 면 `destinationExists`. 통과하면 폴더는 합치고 파일은 `rename(2)` 로 **원자적으로** 교체한다(옛 파일이 지워진 채 남는 순간이 없다).
5. 실패 · 취소 시 임시 폴더를 지운다 (`defer` 로 보장).

> 이미 있는 폴더에 합칠 때(4번 두 번째) 옮기는 도중 입출력 에러가 나면 일부만 옮겨질 수 있다 — 각 파일은 옛 것 또는 새 것 중 하나다. 이 경우만 "최선의 노력"이다.

- `ArchiveReader.extract(_:to:)`(항목 하나)와 `data(for:)` 도 같은 규칙이다 — 검증 전 내용은 밖으로 나오지 않는다. `data(for:)` 는 메모리 버퍼에 풀고 검증이 끝나야 돌려준다.

---

## 10. zip 형식

### 10.1 읽기
1. 파일 끝 22 + 65,535 바이트 안에서 **EOCD**(`0x06054b50`)를 뒤에서부터 찾는다. 후보는 ⓐ 주석 길이가 파일 끝과 정확히 맞고 ⓑ 목차 끝(오프셋 + 크기)이 EOCD 바로 앞이거나 Zip64 locator 가 바로 앞에 있어야 한다 — 주석 안에 넣은 가짜 EOCD 를 거른다. (앞에 다른 데이터가 붙은 자체 압축 해제 파일은 지원하지 않는다.)
2. EOCD 바로 앞에 **Zip64 EOCD locator**(`0x07064b50`)가 있으면 → **Zip64 EOCD**(`0x06064b50`)를 읽어 항목 수 · 목차 크기 · 목차 오프셋을 64비트로 얻는다.
3. **목차**(`0x02014b50`)를 끝까지 읽는다. 로컬 헤더를 앞에서부터 훑지 않는다 — data descriptor(플래그 bit 3)를 쓴 zip 도 목차에는 크기가 있다.
4. 항목의 32비트 필드가 `0xFFFFFFFF`(디스크 번호는 `0xFFFF`)면 **Zip64 extra field(`0x0001`)** 에서 값을 꺼낸다. 순서는 해제 크기 → 압축 크기 → 로컬 헤더 오프셋 → 디스크 번호이고, **`0xFFFFFFFF` 인 필드만** 들어 있다.
5. 목차 오프셋으로 **로컬 헤더**(`0x04034b50`)에 가서, **로컬 헤더의** 이름 길이 · extra 길이로 데이터 시작 위치를 계산한다(목차와 로컬의 extra 길이는 다를 수 있다).
6. 디스크 번호가 0 이 아니거나 디스크 수가 1 보다 크면 → `unsupported("multi-disk")`.

### 10.2 쓰기
- 항목마다 **로컬 헤더(크기 · CRC 자리 비움) → 데이터 스트리밍 → 되돌아가 크기 · CRC 덮어쓰기.** data descriptor 는 쓰지 않는다 (되돌아갈 수 없는 저장소는 지원하지 않는다 — `ArchiveWritable.write(_:at:)` 가 필수).
- **Zip64 판단** (`.automatic`):
  - 항목: 원본 크기가 `0xFFFFFFFF` 이상이거나 모르면(사용자 저장소 스트림 등) 로컬 헤더에 Zip64 extra 자리를 **미리 확보**한다. 크기를 다 쓴 뒤 결과가 32비트에 들어가면 값만 채운다.
  - 로컬 헤더 오프셋이 `0xFFFFFFFF` 이상이면 목차 항목에 Zip64 extra.
  - 항목 수 ≥ 65,535 · 목차 크기/오프셋 ≥ `0xFFFFFFFF` → Zip64 EOCD + locator 를 쓴다.
  - `.always` = 모든 항목과 EOCD 에 Zip64. `.never` = 필요해지면 `unsupported("zip64 disabled")`.
- `version needed`: 저장 10 · DEFLATE 20 · Zip64 45 · AES 51 — **여러 조건이면 가장 큰 값.**
- `version made by` = Unix(3) · 6.3. Unix 권한을 `external attributes` 상위 16비트에 넣는다 (원본 권한, 없으면 파일 `0644` · 폴더 `0755`).
- 날짜: DOS 날짜·시간 (1980년 이전은 1980-01-01, 초는 2초 단위) + **0x5455 확장 시각**(수정 시각, 초 단위 Unix 시간)을 함께 쓴다.
- 원본이 128 KiB 이상이면 **앞 64 KiB 를 먼저 압축해 보고** 97% 이상이면 처음부터 저장 방식으로 쓴다 — 사진 · 영상 · zip 을 두 번 쓰지 않게. 그래도 DEFLATE 결과가 원본 이상이면 그 항목만 **저장 방식으로 다시 쓴다** (안전망).
- 원본 파일은 `O_NOFOLLOW` 로 연다 — lstat 으로 확인한 뒤 링크로 바뀌어도 따라가지 않는다.
- 빈 폴더는 `이름/` 항목으로 넣는다. 심볼릭 링크를 만나면 `unsupported("symlink")`.
- 원자성: 파일 저장소는 같은 폴더의 임시 파일에 쓰고 `commit()` 에서 최종 경로로 옮긴다.

### 10.3 스트리밍
- **64 KiB 단위**로 읽고 쓴다. 파일 전체를 메모리에 올리지 않는다 (메모리 저장소 제외).
- DEFLATE: `compression_stream` + `COMPRESSION_ZLIB` (= 헤더 없는 raw DEFLATE, zip 이 요구하는 형식).
- CRC32: IEEE 다항식 `0xEDB88320`, **slice-by-8** 테이블로 직접 구현 (zlib 의존 없음). 공개 타입 `CRC32` — 사용자 스킴에서도 쓸 수 있다.
- 압축 크기 0 인 빈 항목은 방식과 관계없이 빈 내용으로 본다(해제기를 부르지 않는다).
- async 해제는 항목 사이마다 `Task.yield()` 한다. 항목 하나를 푸는 동안은 동기 작업이다.

---

## 11. 암호화 방식 상세

### 11.1 WinZip AES

**헤더**
- 압축 방식 = **99**, 플래그 bit 0 = 1, `version needed` ≥ 51.
- extra field `0x9901` (데이터 7바이트):

| 오프셋 | 크기 | 값 |
| --- | --- | --- |
| 0 | 2 | vendor version — 1 = AE-1, 2 = AE-2 |
| 2 | 2 | vendor ID — `"AE"` (`0x41 0x45`) |
| 4 | 1 | 강도 — 1 = 128, 2 = 192, 3 = 256 |
| 5 | 2 | 실제 압축 방식 |

**데이터 영역** (헤더의 "압축 크기"에 전부 포함):

```
salt (8 / 12 / 16) | 비밀번호 확인값 (2) | 암호문 (n) | 인증 코드 (10)
```

**키 만들기**
- `CCKeyDerivationPBKDF(kCCPBKDF2, password, salt, kCCPRFHmacAlgSHA1, 1000, out, 2 × keyLength + 2)`
- 출력을 `AES 키 | HMAC 키 | 확인값 2` 로 나눈다 (키 길이 16 / 24 / 32).
- salt 는 항목마다 `SecRandomCopyBytes` 로 새로 만든다.
- 파생 키(`AESKeys`)는 참조 타입이고 해제될 때 0 으로 덮는다(최선의 노력).

**AES-CTR — 🔴 가장 틀리기 쉬운 곳**
- 카운터는 128비트, **1 에서 시작해 little-endian 으로 증가**한다. nonce 없음(나머지 0).
- CommonCrypto 의 `kCCModeCTR` 은 **big-endian 으로 증가**하므로 **그대로 쓰면 결과가 틀린다.**
- 구현: `CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, key)` 로 카운터 블록을 직접 암호화해 키스트림을 만들고 XOR. 복호화도 같은 연산. 마지막 블록은 키스트림을 잘라 쓴다.

**인증**
- `CCHmac(kCCHmacAlgSHA1, hmacKey)` 를 **암호문**에 대해 계산, 앞 10바이트. 비교는 **상수 시간**.
- 순서: 쓰기 = 압축 → 암호화 → HMAC / 읽기 = HMAC 누적 + 복호화 → 해제.

**AE-1 / AE-2**
- **쓸 때는 AE-2** — CRC 를 0 으로 둔다(원문 정보 노출 방지, 무결성은 HMAC).
- 읽을 때 AE-1 이면 HMAC 과 CRC 를 **둘 다** 검증한다.

### 11.2 ZipCrypto — 지원하지 않음

- 0.1.0 개발 중 구현했다가 **태그 전에 뺐다**(2026-09-29). 이유: 깨진 암호 · 라이브러리가 직접 구현한 유일한 암호 알고리즘이라 쓰는 앱의 수출 규정 판단(App Store Connect 암호화 질문)을 흐림 · 쓰는 곳 없음.
- 판정: 플래그 bit 0 이 켜져 있고 AES(방식 99)도 PKWARE SES(bit 6)도 아니면 ZipCrypto 로 보고, `Entry.encryption` 에 `zipcrypto` 로 보여 준다. 해제하면 `unsupported("ZipCrypto (traditional PKWARE encryption) is not supported")`.
- 다시 필요해지면 `EncryptionScheme` 으로 구현해 별도 모듈에서 `registering(_:)` 한다 — 확장 지점(`requiresCRCBeforeEncryption` · `integrityFailureIndicatesWrongPassword`)은 그 용도로 남겨 둔다.

---

## 12. 테스트

픽스처는 **테스트 중에 시스템 도구로 만든다** (도구가 없으면 그 테스트만 skip). 바이너리 픽스처를 커밋하지 않는다. 공격 zip 은 테스트 안의 원시 바이트 빌더(`RawZip`)로 만든다.

| 분류 | 내용 |
| --- | --- |
| 호환 (해제) | Info-ZIP `zip`(일반 · 표준 입력 스트림 = data descriptor) · `ditto -c -k` · `python3 zipfile`(unseekable 스트림 = data descriptor) · `bsdtar --format zip` |
| 호환 (생성) | Satchel 산출물 → `unzip -t` · `python3 testzip()` · `unzip` 해제 · `bsdtar` 해제 후 트리 비교 |
| 왕복 | 저장/DEFLATE × Zip64 automatic/always, 빈 파일 · 빈 폴더 · 한글 이름 · 64 KiB 경계(65,536 · 65,537), 압축 안 되는 데이터 → 저장 방식 대체, 권한 · 수정 시각 · 주석 |
| AES (해제) | **`bsdtar`(libarchive) 로 만든 AES-256 · AES-128** — 독립 구현. 맞음 / 틀림 / 없음 |
| AES (생성) | Satchel AES-128/192/256 → **`bsdtar` 로 해제** (독립 구현 교차 검증), 틀린 비밀번호는 bsdtar 도 거부 · `7zz t` (설치 시) |
| ZipCrypto 거부 | `zip -P` · `bsdtar zipcrypt` 로 만든 zip → 목록에 `zipcrypto`, 해제는 `unsupported(ZipCrypto…)` · 대상 폴더 미생성 |
| 비밀번호 후보 | **CP949 후보**(bsdtar AES 에 셸 printf 로 CP949 원시 바이트) · NFD 후보 (Process 인수가 NFD 로 바뀌는 현상으로 재현) |
| 무결성 | AES 암호문 1비트 변조 → `corrupted(authentication failed)` |
| Zip64 | `.always` 산출물 → unzip · python · bsdtar, python `force_zip64` 읽기, Info-ZIP `-fz` 읽기, **항목 65,540개**(Zip64 EOCD), `.never` 거부, `maxEntryCount`, **4 GiB 초과 항목 왕복**(`SATCHEL_LARGE_TESTS=1`) |
| 인코딩 | CP949 이름(bit 11 없음) · bit 11 없는 UTF-8 · CP437 대체 · 강제 인코딩 · 0x7075 CRC 일치/불일치 · CP949 쓰기 + 0x7075 (python `metadata_encoding='cp949'` 로 확인) · 이모지 CP949 실패 · NFD → NFC |
| 공격 | `../` · `a/../../` · `..\` · 절대 경로 · 드라이브 문자 · UNC · 제어 문자 · 빈 이름 · 심볼릭 링크 · 중복 · 대소문자 중복 · NFC/NFD 중복 · 파일/폴더 이름 충돌 · 로컬/목차 이름 불일치 · 선언 크기 초과 · 비율 · 총량 상한 · 겹침 · 잘린 파일 · 주석 안 가짜 EOCD · 멀티 디스크 · PKWARE SES · 미지원 압축 방식 · 대상 폴더의 기존 심볼릭 링크 · setuid 제거 · 쓰기 쪽 위험 이름 거부 |
| 원자성 | 중간 항목 CRC 실패 · 비밀번호 틀림 · 취소 시 대상 폴더 미생성 · 임시 폴더 없음 · 폴더 밖에 쓰지 않음 · 버린 writer 는 파일을 남기지 않음 |
| 제공자 | 틀림 → 재시도(시도 번호·이유) · 맞은 비밀번호 재사용(한 번만 묻는지) · `options.password` 우선 · `.passwords` 후보 · `.skipEntry` · `.cancel` · Task 취소 |
| API | 대상 폴더 충돌/덮어쓰기(합치기) · 기존 zip 보호 · 항목 단위 API · 다른 zip 의 Entry 거부 · 진행률(생성·해제 바이트 일치) · `Progress.cancel()` · 숨김 파일 옵션 |
| 확장 지점 | **공개 API 만으로**(`@testable` 없이) 사용자 코덱 · 사용자 스킴 등록 → 왕복, 등록 안 한 쪽은 `unsupported` |
| 리뷰 회귀 | 조작된 Zip64 locator 오프셋(오버플로 트랩 없이 거부) · 빈 비밀번호 = 틀림 · overwrite 가 폴더를 파일로 바꾸지 않음 · 깊은 경로 거부 + 트리 성능 · 쓰기가 등록소를 따름 · 내장 스킴 교체 시 우선순위 유지 · group/other 쓰기 제거 · 데이터 없는 DEFLATE 빈 항목 · slice-by-8 CRC 기준값 · 압축 안 되는 데이터 미리 판정 · 메모리 API 상한 · 항목 단위 API 겹침 거부 |
| 비밀 노출 | `Password` 의 `description` · `debugDescription` · `dump()`, 옵션 `dump()`, 에러 문자열에 비밀번호 없음 |

- 🔴 **AES 는 반드시 독립 구현으로 교차 검증한다.** 암호화와 복호화를 둘 다 우리가 짜면 같은 실수(예: §11.1 카운터 방향)가 서로 맞물려 왕복 테스트를 통과한다. macOS 기본 `bsdtar`(libarchive 3.7) 가 AES-128/256 을 쓰고 읽을 수 있어 7-Zip 없이도 검증된다. AES-192 는 libarchive 가 쓰지 못해 해제 방향만 bsdtar 로 확인한다.
- 픽스처는 **합성 데이터만** 쓴다. 실제 서비스에서 받은 zip 은 넣지 않는다.

## 13. 샘플 앱 (`Example/SatchelExample.swiftpm`)

- Swift Playgrounds 앱 패키지 형식 — Xcode 로 폴더를 열면 iOS 앱으로 실행된다. 라이브러리는 `../..` 로컬 경로로 연결.
- SwiftUI · **iOS 16+** — 라이브러리(iOS 15)보다 높은 이유는 `NavigationStack` · `ShareLink`(둘 다 iOS 16). 샘플은 앱에 들어가지 않아 코드를 짧게 두는 쪽을 택했다. iOS 15 로 내리려면 `NavigationView` · `UIActivityViewController` 로 바꾼다. 자세한 건 `Example/README.md`.
- 서명 팀은 비워 두었다 — 실기기 실행 시 각자 고른다. Xcode 가 `Package.swift` 에 `teamIdentifier` 를 써 넣으므로 커밋하지 않는다.
- **열기**: 파일 선택 → 항목 목록(암호화 여부 · 방식 · Zip64 · 크기 표시).
- **해제**: `PasswordProvider` 를 구현한 `@MainActor` 객체가 `SecureField` 알림창을 띄운다. 틀리면 "다시 입력"(시도 횟수 표시), 건너뛰기 · 취소 버튼. 진행률 막대 + 취소.
- **생성**: 파일 선택 → 압축 방식 · 암호화 방식(AES 강도) · 이름 인코딩 · Zip64 모드 → 공유 시트.

---

## 14. 릴리스

- **0.1.0 에 전부 넣는다** — §1.1 의 모든 기능 · §5 확장 지점 공개 · 샘플 앱.
- 태그는 `0.1.0` 형식(`v` 접두어 없음 — SPM 이 그대로 읽는다).
- `1.0.0` 전까지는 마이너 버전에서 공개 API(확장 지점 포함)가 바뀔 수 있다. 쓰는 쪽은 `exact:` 로 고정한다.

## 15. 공개 전 점검 (push 전 매번)

- [ ] 특정 회사 · 제품 식별자(이름, 도메인, 내부 경로, 티켓 번호)가 소스 · 주석 · 커밋 메시지 · 픽스처에 없다
- [ ] 픽스처가 전부 합성 파일이다
- [ ] 비밀번호 · 키가 로그 · 테스트 출력에 찍히지 않는다
- [ ] 빌드 산출물(`.build/`, `DerivedData`, `*.xcuserstate`)이 커밋에 없다

---

## 변경 이력

| 날짜 | 내용 |
| --- | --- |
| 2026-09-29 | 초안 — 압축 · 해제 · AES-256 최소 범위 |
| 2026-09-29 | 범위 확장 — AES 128/192 · ZipCrypto(생성은 opt-in) · Zip64 읽기/쓰기 · CP949(이름·비밀번호) · 비밀번호 제공자 · 확장 지점 공개(0.1.0 부터) · Reader/Writer · 메모리 저장소 · 진행률/취소. 버전 0.1.0 시작, 릴리스 단위 재편 |
| 2026-09-29 | 0.1.0 구현 — 릴리스 단일화, `ReadOptions` 분리 · `CreateOptions`→`WriteOptions`, 스킴 우선순위(나중 등록 먼저), 비밀번호 NFC/NFD 후보, EOCD 정합성 검사, 대상 폴더 기존 링크 거부 · `O_NOFOLLOW`, 파일 `u+rw` 보장, 테스트 픽스처를 시스템 도구로 생성(bsdtar 를 AES 독립 기준으로), 샘플 앱 `.swiftpm` |
| 2026-09-29 | 코드 리뷰(5개 차원, 24건) 반영 — Zip64 locator 오버플로(P1), 경로 트리, 원자적 파일 교체 · 파일↔폴더 충돌 거부, 쓰기 경로 등록소 경유, `storesCRC(for:)`, 스킴 제자리 교체, 빈 비밀번호 = 틀림, `allowedEncryption` 기본 nil, `ExtractLimits.inMemory`, 8 KiB 해제 입력, 압축률 미리 판정, `O_NOFOLLOW` 원본 읽기, group/other 쓰기 제거, slice-by-8 CRC, 파생 키 지우기 |
| 2026-09-29 | 최소 지원 버전 iOS 13 / macOS 10.15 → **iOS 15 / macOS 12** (쓰는 앱의 상향 계획에 맞춤) |
| 2026-09-29 | **ZipCrypto 제거**(읽기·쓰기, 태그 전) — 깨진 암호 · 자체 구현 암호라 쓰는 앱의 수출 규정 판단을 흐림 · 쓰는 곳 없음. 목록에는 `zipcrypto` 로 보이고 해제는 `unsupported`. 원칙 6(암호 알고리즘 직접 구현 금지) 추가 |
