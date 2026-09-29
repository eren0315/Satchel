# Satchel 설계

> 가방(satchel)에 파일을 넣고, 꺼내고, 잠근다 — **순수 Swift zip 라이브러리.**
> 압축 · 해제 · 암호화(WinZip AES / ZipCrypto) · Zip64 · 한국어 인코딩(CP949)을 지원하고, 압축 방식과 암호화 방식을 **공개 프로토콜로 끼워 넣을 수 있다.**
> 외부 의존성 없음 — `Foundation` · `Compression` · `CommonCrypto` · `Security` 만 쓴다.

- 상태: **설계 (0.x)** — 이 문서가 설계의 단일 기준이다. 바뀌면 이 문서를 고치고 맨 아래 변경 이력에 남긴다.
- 버전: **0.1.0 부터 시작**. `1.0.0` 전까지는 마이너 버전(0.x → 0.y)에서 공개 API 가 바뀔 수 있다(SemVer 0.x 규칙). 쓰는 쪽은 `exact:` 로 고정하길 권한다.

---

## 1. 범위

### 1.1 지원

| 영역 | 해제(읽기) | 생성(쓰기) |
| --- | --- | --- |
| 압축 방식 | 저장(0) · DEFLATE(8) · 등록한 사용자 코덱 | 저장 · DEFLATE · 등록한 사용자 코덱 |
| 암호화 | WinZip AES 128/192/256 (AE-1·AE-2) · ZipCrypto · 등록한 사용자 스킴 | **AES-256 · AE-2 가 기본**, AES 128/192 선택 가능, ZipCrypto 는 **직접 켜야만** (`.legacyZipCrypto`) |
| Zip64 | ✅ | ✅ 필요할 때 자동 / 항상 / 끔 |
| 파일 이름 인코딩 | UTF-8(bit 11) · 유니코드 경로 extra(0x7075) · **CP949** · CP437 — 자동 판정 또는 지정 | UTF-8(기본) · **CP949**(+0x7075 로 UTF-8 병기) |
| 비밀번호 인코딩 | UTF-8 · **CP949** · CP437 후보를 차례로 시도 | 지정한 인코딩 1개 (기본 UTF-8) |
| 비밀번호 전달 | 고정 비밀번호(동기) · **비밀번호 제공자**(async, 항목별 · 재시도 · 건너뛰기 · 취소) | 고정 비밀번호, 항목별 지정 가능 |
| 입출력 | 파일 · 메모리(`Data`) · 사용자 저장소 | 파일 · 메모리 · 사용자 저장소 |
| 부가 기능 | 항목 목록 · 항목 하나만 `Data` 로 · 비밀번호 검증만 · 진행률 · 취소 | 진행률 · 취소 |

### 1.2 지원하지 않음 — 만나면 `ZipError.unsupported` 로 명시적으로 실패

| 항목 | 이유 |
| --- | --- |
| PKWARE Strong Encryption (플래그 bit 6) · 목차 암호화 (bit 13) | 독점 규격, 쓰이는 곳이 거의 없다 |
| 분할(멀티 디스크) zip | 필요성 낮음 |
| bzip2 · LZMA · deflate64 · zstd 등 | Apple 프레임워크로 처리할 수 없다 → **사용자 코덱으로 끼워 넣을 수 있게만** 한다 (§5) |
| 심볼릭 링크 항목 | 경로 탈출 수단. 읽기·쓰기 모두 거부 |
| 기존 zip 에 항목 추가·삭제 (in-place 수정) | 새로 만드는 것으로 대신한다 |
| UI | 라이브러리 밖. 비밀번호 입력 창은 **샘플 앱**에서만 보여 준다 |

### 1.3 원칙
1. **기본값은 안전한 쪽.** 생성 기본 암호화는 AES-256. 약한 방식은 이름부터 `legacy`.
2. **외부에서 받은 zip 을 믿지 않는다.** 경로 탈출 · 심볼릭 링크 · 크기 폭탄 · 무결성 위반을 막는다 (§8).
3. **해제는 전부 되거나 아무것도 남지 않는다** (§9).
4. **비밀번호·키는 로그·에러·`description` 어디에도 나오지 않는다.**
5. **모르는 것을 조용히 넘기지 않는다.** 지원하지 않는 기능은 이유를 담아 실패한다.

---

## 2. 패키지 구성

```
Satchel/
├── Package.swift                 // swift-tools-version 6.0 · Swift 6 언어 모드 · iOS 13 / macOS 10.15
├── LICENSE                       // 0BSD
├── README.md
├── docs/DESIGN.md                // 이 문서
├── Sources/Satchel/
│   ├── API/                      // Zip · ArchiveReader · ArchiveWriter · 옵션 · Entry · ZipError
│   ├── Password/                 // Password · PasswordProvider · 후보 인코딩
│   ├── Extension/                // 공개 확장 지점: CompressionCodec · EncryptionScheme · ByteTransform · 저장소 · ZipRegistry
│   ├── Format/                   // 로컬 헤더 · 목차 · EOCD · Zip64 EOCD/locator · extra field · DOS 시각
│   ├── Codecs/                   // StoreCodec · DeflateCodec (Compression 프레임워크)
│   ├── Encryption/               // WinZipAES · ZipCrypto
│   ├── Text/                     // 파일 이름·비밀번호 인코딩 (UTF-8 · CP949 · CP437) · NFC 정규화
│   ├── Safety/                   // 항목 경로 검증 · 상한 검사
│   ├── Storage/                  // 파일 · 메모리 저장소, 64 KiB 버퍼
│   └── Checksum/                 // CRC32
├── Tests/SatchelTests/
│   └── Fixtures/                 // 합성 zip 만. 실제 서비스 파일은 넣지 않는다
├── Scripts/make-fixtures.sh      // 픽스처 재생성 (zip · ditto · python3 · 7zz · iconv)
└── Example/                      // 샘플 앱 (SwiftUI)
```

- **iOS 13 / macOS 10.15**: 연결할 앱의 최소 지원 버전보다 높으면 연결이 안 된다. macOS 는 `swift test` 를 시뮬레이터 없이 돌리기 위해 넣는다. async API 는 Swift Concurrency back-deploy 로 iOS 13 에서 동작한다.
- **Swift 6 언어 모드**: 엄격한 동시성 검사로 스레드 안전을 컴파일러가 보장하게 한다. 쓰는 쪽은 Xcode 16 이상이어야 한다.
- **의존성 0개** (테스트 포함). 교차 검증은 macOS 기본 `unzip` 과, 설치돼 있으면 `7zz` 로 한다 (§12).
- **공개 타입 이름을 모듈 이름 `Satchel` 과 같게 두지 않는다** — `Satchel.X` 로 한정할 때 모듈과 타입이 충돌한다.

---

## 3. 구조

```
┌ 공개 API ───────────────────────────────────────────────────────────┐
│  Zip (간편 함수)      ArchiveReader            ArchiveWriter          │
│  Password · PasswordProvider · CreateOptions · ExtractOptions · Entry │
└──────────────────────────────┬──────────────────────────────────────┘
┌ 항목 파이프라인 ───────────────┴──────────────────────────────────────┐
│  읽기: 저장소 → [복호화 + 무결성] → [해제 + CRC + 크기 상한] → 출력    │
│  쓰기: 원본 → [압축] → [암호화 + 무결성] → 저장소 (헤더는 되돌아가 보정) │
└──────────────────────────────┬──────────────────────────────────────┘
┌ 등록소 ZipRegistry ───────────┴──────────────────────────────────────┐
│  CompressionCodec: Store · Deflate · (사용자)                          │
│  EncryptionScheme: WinZipAES · ZipCrypto · (사용자)                    │
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
                              options: CreateOptions = .init()) throws -> CreateResult

    /// 고정 비밀번호(또는 없음)로 전부 푼다.
    @discardableResult
    public static func extract(_ archiveURL: URL, to destinationURL: URL,
                               options: ExtractOptions = .init()) throws -> ExtractResult

    /// 비밀번호 제공자에게 항목마다 물어 가며 푼다. Task 취소를 따른다.
    @discardableResult
    public static func extract(_ archiveURL: URL, to destinationURL: URL,
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

    public func extract(_ entry: Entry, to url: URL, password: Password? = nil) throws
    public func data(for entry: Entry, password: Password? = nil) throws -> Data
    public func verify(_ password: Password, for entry: Entry) throws -> PasswordCheck
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
    public func add(_ data: Data, as path: String, modificationDate: Date = .now, options: EntryOptions? = nil) throws
    public func addEmptyDirectory(as path: String) throws

    public func finish() throws              // 파일·사용자 저장소
    public func finishData() throws -> Data  // 메모리
}
```

- `ArchiveWriter` 는 순서대로 쓰는 객체라 한 스레드에서만 쓴다 (`Sendable` 아님).
- `finish()` 를 부르지 않고 해제되면 임시 파일을 지우고 결과를 만들지 않는다.

### 4.3 옵션

```swift
public struct CreateOptions: Sendable {               // = WriteOptions + 폴더 순회 옵션
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

public struct EntryOptions: Sendable {                // 항목 단위 덮어쓰기 (nil 인 값은 CreateOptions 를 따른다)
    public var compression: CompressionMethod?
    public var encryption: EncryptionMethod?
    public var password: Password?
}

public struct ExtractOptions: Sendable {
    public var password: Password? = nil              // 동기 API 용
    public var overwrite: Bool = false
    public var filenameEncoding: FilenameEncoding = .automatic
    public var allowedEncryption: Set<EncryptionIdentifier> = [.winZipAES, .zipCrypto]
    public var limits: ExtractLimits = .default
    public var restoresModificationDate: Bool = true
    public var restoresPermissions: Bool = true       // 실행 비트 등. setuid/setgid/sticky 는 항상 제거
    public var registry: ZipRegistry = .standard
    public var progress: Progress? = nil
}

public struct ExtractLimits: Sendable {
    public var maxEntryCount: Int = 100_000
    public var maxTotalUncompressedSize: UInt64 = 8 << 30   // 8 GiB
    public var maxCompressionRatio: UInt64 = 1_000          // 항목별 해제/압축 비율 상한
    public static let `default` = ExtractLimits()
    public static let unlimited: ExtractLimits              // 쓰는 쪽이 책임질 때만
}

public enum CompressionMethod: Sendable, Hashable {
    case store, deflate
    case custom(methodID: UInt16)                     // 등록소에서 코덱을 찾는다
}

public enum EncryptionMethod: Sendable, Hashable {
    case none
    case aes(AESStrength = .bits256)
    case legacyZipCrypto                              // ⚠️ 약한 암호. 기본 도구 호환이 꼭 필요할 때만
    case custom(EncryptionIdentifier)
}
public enum AESStrength: Sendable { case bits128, bits192, bits256 }

public enum Zip64Mode: Sendable { case automatic, always, never }

public enum FilenameEncoding: Sendable, Hashable {
    case automatic                                    // 읽기 전용: §7.1 순서로 판정
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

> 0.x 동안은 이 시그니처도 마이너 버전에서 바뀔 수 있다. 내장 구현(Store · Deflate · WinZipAES · ZipCrypto)이 모두 이 프로토콜로 만들어진다.

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
    public static let zipCrypto = EncryptionIdentifier(rawValue: "zipcrypto")
}

public protocol EncryptionScheme: Sendable {
    var identifier: EncryptionIdentifier { get }

    // ── 읽기 ──
    /// 이 항목이 이 스킴으로 암호화됐는지 헤더(플래그 · 압축 방식 ID · extra field)로 판정
    func matches(_ header: EntryHeader) -> Bool
    /// 데이터 맨 앞에서 읽어야 할 바이트 수 (AES: salt + 확인값, ZipCrypto: 12)
    func prefixLength(for header: EntryHeader) -> Int
    /// 맨 뒤 바이트 수 (AES: 인증 코드 10, ZipCrypto: 0)
    func trailerLength(for header: EntryHeader) -> Int
    /// 비밀번호를 빠르게 확인하고, 맞으면 복호화기를 만든다
    func makeDecryptor(password: [UInt8], header: EntryHeader, prefix: [UInt8]) throws -> DecryptorResult

    // ── 쓰기 ──
    /// 암호화하기 전에 원문 CRC 가 필요한가 (ZipCrypto: 헤더 확인 바이트에 CRC 를 쓴다)
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
    var size: UInt64 { get throws }
    func read(at offset: UInt64, count: Int) throws -> [UInt8]   // 여러 스레드에서 동시에 불려도 안전해야 한다
}

public protocol ArchiveWritable: AnyObject {
    var position: UInt64 { get }
    func write(_ bytes: [UInt8]) throws
    func write(_ bytes: [UInt8], at offset: UInt64) throws        // 헤더 보정용 (되돌아가 덮어쓰기)
    func commit() throws                                          // 성공 확정 (파일: 임시 → 최종 이동)
    func discard()                                                // 실패 시 정리
}
```

### 5.5 등록소

```swift
public struct ZipRegistry: Sendable {
    public static let standard: ZipRegistry           // Store · Deflate · WinZipAES · ZipCrypto
    public init(codecs: [any CompressionCodec], schemes: [any EncryptionScheme])
    public func registering(_ codec: any CompressionCodec) -> ZipRegistry     // 같은 methodID 면 교체
    public func registering(_ scheme: any EncryptionScheme) -> ZipRegistry    // 같은 identifier 면 교체
}
```

- 등록소는 **값 타입**이다. 전역 상태를 바꾸지 않고 옵션으로 넘긴다 — 한 앱 안에서 서로 다른 설정이 섞여도 안전하다.
- 암호화 판정은 등록된 스킴을 순서대로 `matches` 에 물어 **첫 번째로 맞는 것**을 쓴다. 아무것도 안 맞는데 플래그 bit 0 이 켜져 있으면 `unsupported`.

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

- **해제**: 후보 바이트열을 만든 뒤 같은 것은 합친다(ASCII 비밀번호는 셋이 모두 같다). 표현할 수 없는 인코딩(예: 한글 → CP437)은 건너뛴다.
- **생성**: `encodings` 의 **첫 번째**만 쓴다. AES 의 기본은 UTF-8.
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
| ZipCrypto | 확인 바이트 1개 (통과 확률 1/256) | CRC 불일치 | 둘 다 → **`wrongPassword`** |

- ZipCrypto 는 무결성 검사 수단이 CRC 뿐이라 **틀린 비밀번호와 손상을 구분할 수 없다.** 1/256 확률로 틀린 비밀번호가 확인 바이트를 통과하므로, CRC 불일치를 비밀번호 틀림으로 본다(7-Zip 과 같은 판단). 진짜 손상된 파일이면 제공자가 계속 다시 물을 수 있고, 제공자가 `cancel` 로 끝낸다.
- 후보(인코딩 · `passwords`)를 시도할 때 **확인값을 통과한 후보만** 복호화까지 간다. 통과한 후보가 CRC/HMAC 에서 실패하면 다음 후보로 넘어간다.

### 6.4 `verify(_:for:)`
- 풀지 않고 비밀번호가 맞는지만 본다.
- `PasswordCheck`: `.correct`(무결성까지 확인) / `.likelyCorrect`(빠른 확인만 통과 — 기본) / `.wrong`.
- `thorough: true` 를 주면 항목 전체를 복호화해 무결성까지 검증한다(비용 = 해제와 같음, 쓰기 없음).

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
| 파일 `a` 와 폴더 `a/` 가 함께 있음 | `unsafeEntryPath` |
| 심볼릭 링크 (Unix 모드 `S_IFLNK`) | `unsafeEntryPath` |
| 로컬 헤더 이름 ≠ 목차 이름 | `corrupted` (도구마다 다르게 풀리는 zip 을 막는다) |

### 8.2 크기 폭탄
- 사전 점검: 항목 수 ≤ `maxEntryCount`, 선언 해제 크기 합 ≤ `maxTotalUncompressedSize`, 항목별 `해제 / 압축` ≤ `maxCompressionRatio` (압축 크기 0 인 빈 파일은 제외).
- 해제 중: **실제로 나온 바이트가 선언 크기를 넘는 순간 중단** → `corrupted`. 선언 크기를 속인 zip 을 막는다.
- 겹치는 항목(두 목차 항목이 같은 데이터 영역을 가리킴 — "겹침 폭탄") → 데이터 영역 범위가 서로 겹치면 `corrupted`.

### 8.3 권한
- 복원하는 건 `rwx` 비트뿐. **setuid · setgid · sticky 는 항상 제거**한다.
- 해제한 폴더에는 최소 `u+rwx` 를 보장한다 (안에 쓸 수 있어야 한다).

---

## 9. 해제의 원자성

1. **사전 점검** — 목차를 끝까지 읽고 §8 규칙 · 상한 · 지원 여부(압축 방식 · 암호화 방식 · `allowedEncryption`) · 비밀번호 필요 여부(동기 API)를 **아무것도 쓰기 전에** 전부 검사한다.
2. `destinationURL` 의 **부모 폴더** 안에 `.satchel-<UUID>` 임시 폴더를 만든다 (같은 볼륨 → 이동이 원자적).
3. 항목마다 임시 폴더에 풀고 **CRC · HMAC 을 검증한 뒤** 다음 항목으로 간다.
4. 전부 성공하면:
   - `destinationURL` 이 없으면 → 임시 폴더를 **통째로 이름 변경** (원자적)
   - 있으면 → 최상위 항목을 옮긴다. `overwrite == false` 에 같은 이름이 있으면 **옮기기 전에** 전부 검사해 `destinationExists`
5. 실패 · 취소 시 임시 폴더를 지운다 (`defer` 로 보장).

> 이미 있는 폴더에 합칠 때(4번 두 번째) 옮기는 도중 입출력 에러가 나면 일부만 옮겨질 수 있다. 이 경우만 "최선의 노력"이다.

- `ArchiveReader.extract(_:to:)`(항목 하나)와 `data(for:)` 도 같은 규칙이다 — 검증 전 내용은 밖으로 나오지 않는다. `data(for:)` 는 메모리 버퍼에 풀고 검증이 끝나야 돌려준다.

---

## 10. zip 형식

### 10.1 읽기
1. 파일 끝 22 + 65,535 바이트 안에서 **EOCD**(`0x06054b50`)를 뒤에서부터 찾는다. 찾은 EOCD 의 주석 길이가 파일 끝과 정확히 맞아야 한다(주석 안의 가짜 시그니처 방지).
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
- DEFLATE 결과가 원본보다 커지면 그 항목만 **저장 방식으로 다시 쓴다** (원본을 다시 읽는다).
- 빈 폴더는 `이름/` 항목으로 넣는다. 심볼릭 링크를 만나면 `unsupported("symlink")`.
- 원자성: 파일 저장소는 같은 폴더의 임시 파일에 쓰고 `commit()` 에서 최종 경로로 옮긴다.

### 10.3 스트리밍
- **64 KiB 단위**로 읽고 쓴다. 파일 전체를 메모리에 올리지 않는다 (메모리 저장소 제외).
- DEFLATE: `compression_stream` + `COMPRESSION_ZLIB` (= 헤더 없는 raw DEFLATE, zip 이 요구하는 형식).
- CRC32: IEEE 다항식 `0xEDB88320`, slice-by-8 테이블로 직접 구현 (zlib 의존 없음).

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

### 11.2 ZipCrypto (전통 PKWARE)

**키 스트림**
- 키 3개 초기값 `0x12345678` · `0x23456789` · `0x34567890`. 비밀번호 바이트마다 `update_keys` (CRC32 테이블 사용).
- 복호화 바이트: `temp = key2 | 2; ((temp * (temp ^ 1)) >> 8) & 0xFF`. 평문으로 `update_keys`.

**헤더 12바이트** (데이터 맨 앞, 압축 크기에 포함)
- 앞 11바이트 난수 + **확인 바이트 1개**.
- 확인 바이트 = CRC 의 상위 바이트. 단 플래그 bit 3(data descriptor)이면 DOS 수정 시각의 상위 바이트 — **읽을 때는 둘 다 처리**한다.
- **쓸 때는 CRC 를 먼저 알아야 한다** → 원본을 한 번 더 읽어 CRC 를 먼저 계산한다(`requiresCRCBeforeEncryption = true`). data descriptor 를 쓰지 않아 옛 도구와도 호환된다.

**정책**
- 생성은 `EncryptionMethod.legacyZipCrypto` 를 **직접 지정했을 때만**. 문서 주석에 약한 암호라는 경고를 단다.
- 해제는 기본 허용 (`allowedEncryption` 에서 뺄 수 있다).

---

## 12. 테스트

| 분류 | 내용 |
| --- | --- |
| 호환 픽스처 (해제) | `zip`(Info-ZIP) · `ditto -c -k` · `python3 zipfile` — 저장/DEFLATE, data descriptor, 빈 폴더, 한글 이름, bit 11 없는 UTF-8 |
| Zip64 픽스처 | `zip -fz`(강제 Zip64) · `python3 zipfile(force_zip64=True)` · 항목 65,536개 zip |
| 인코딩 픽스처 | CP949 이름(bit 11 없음) · CP437 이름 · 0x7075 병기 · 0x7075 CRC 불일치 · NFD 이름 |
| AES 픽스처 | **`7zz` 로 만든 AES-128/192/256** — 우리 구현과 독립된 기준. 비밀번호 맞음 / 틀림 / 없음 / 항목별 다른 비밀번호 / 섞인 zip |
| ZipCrypto 픽스처 | `zip -P` — ASCII 비밀번호, **CP949 비밀번호**(`iconv` 로 바이트 생성), data descriptor 사용본 |
| 공격 픽스처 | `../` · 절대 경로 · 드라이브 문자 · 심볼릭 링크 · 중복 · 대소문자/NFD 중복 · 파일·폴더 이름 충돌 · 로컬/목차 이름 불일치 · 선언 크기 초과 · 비율 폭탄 · 겹침 폭탄 · 잘린 파일 · 주석 안 가짜 EOCD · 멀티 디스크 · PKWARE SES |
| 왕복 | 생성 → 해제: 압축 방식 × 암호화 방식 × Zip64 모드 × 이름 인코딩 조합, 빈 파일, 빈 폴더, 경계 크기(0 · 1 · 65,535 · 65,536 · 65,537 바이트) |
| 교차 검증 (생성) | 비암호화 · ZipCrypto 산출물 → `/usr/bin/unzip -t` 통과. AES 산출물 → `7zz t -p…` 통과 (`7zz` 없으면 skip) |
| 대용량 Zip64 | 4 GiB 초과 항목 왕복 — 환경 변수 `SATCHEL_LARGE_TESTS=1` 일 때만 |
| 원자성 · 취소 | 중간 항목 HMAC 실패 · 취소 · 제공자 `.cancel` 시 해제 폴더가 호출 전과 같고 임시 폴더가 남지 않음 |
| 제공자 흐름 | 틀림 → 재시도 · 맞은 비밀번호 재사용(한 번만 묻는지) · `.skipEntry` · `.passwords` 후보 |
| 확장 지점 | 테스트용 사용자 코덱(예: XOR "압축")과 사용자 스킴을 등록해 왕복 — 확장 지점이 실제로 동작하는지 |
| 비밀 노출 | `Password.description`, 에러 문자열, `dump()` 결과에 비밀번호가 없는지 |

- 🔴 **AES 는 반드시 7-Zip 기준으로 교차 검증한다.** 암호화와 복호화를 둘 다 우리가 짜면 같은 실수(예: §11.1 카운터 방향)가 서로 맞물려 왕복 테스트를 통과한다.
- 픽스처는 **합성 파일만** 쓴다. `Scripts/make-fixtures.sh` 로 언제든 다시 만든다.

---

## 13. 샘플 앱 (`Example/`)

- SwiftUI · iOS 16+ (샘플이라 최소 버전 자유).
- **열기**: 파일 선택 → 항목 목록(암호화 여부 · 방식 · Zip64 · 크기 표시).
- **해제**: `PasswordProvider` 를 구현한 `@MainActor` 객체가 `SecureField` 알림창을 띄운다. 틀리면 "다시 입력"(시도 횟수 표시), 건너뛰기 · 취소 버튼. 진행률 막대 + 취소.
- **생성**: 파일 선택 → 압축 방식 · 암호화 방식(AES 강도 / ZipCrypto 는 경고 문구와 함께) · 이름 인코딩 · Zip64 모드 → 공유 시트.

---

## 14. 진행 순서 · 릴리스

| 버전 | 내용 | 완료 기준 |
| --- | --- | --- |
| **0.1.0** | 읽기 코어 — 형식(Zip64 포함) · 저장/DEFLATE · §8 안전 · §9 원자성 · 이름 인코딩(UTF-8 · 0x7075 · CP949 · CP437) · `ArchiveReader` · `Zip.extract`(동기) | 호환 · Zip64 · 인코딩 · 공격 픽스처 통과 |
| 0.2.0 | 쓰기 코어 — 저장/DEFLATE · Zip64 3모드 · CP949 쓰기 + 0x7075 · NFC · `ArchiveWriter` · `Zip.create` | 왕복 + `unzip -t` 통과 |
| 0.3.0 | 암호화 — `EncryptionScheme` · WinZip AES 128/192/256 · ZipCrypto · `Password` 후보 인코딩 | 7-Zip · `zip -P` 픽스처 + `7zz t` 통과 |
| 0.4.0 | 비밀번호 제공자 · async API · 진행률 · 취소 · `verify` · `data(for:)` · 메모리 저장소 | 제공자 흐름 · 원자성 · 취소 테스트 통과 |
| 0.5.0 | 샘플 앱 · README 사용 예 · DocC | 샘플에서 전 흐름 동작 |

- 확장 지점 프로토콜(§5)은 **0.1.0 부터 공개**한다. 내장 코덱이 첫 사용자다. 0.3.0 에서 암호화 스킴이 붙을 때 프로토콜이 바뀔 수 있다(0.x).
- 태그는 `0.1.0` 형식(`v` 접두어 없음 — SPM 이 그대로 읽는다).
- 0.1.0 만으로 "외부에서 받은 zip 을 안전하게 푸는" 용도는 충분하다.

---

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
