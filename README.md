# Satchel

순수 Swift zip 라이브러리 — **압축 · 해제 · 암호화(WinZip AES / ZipCrypto) · Zip64 · CP949**.
외부 의존성 없이 `Foundation` · `Compression` · `CommonCrypto` · `Security` 만 씁니다.

- 외부에서 받은 zip 을 **안전하게** 풉니다 — 경로 탈출 · 심볼릭 링크 · 압축 폭탄 · 무결성 위반 차단, **전부 되거나 아무것도 남지 않는** 해제
- WinZip AES 128/192/256 (생성 기본값 AES-256 · AE-2), ZipCrypto 해제 (생성은 직접 켤 때만)
- 비밀번호 제공자 — 항목별 비밀번호 · 재시도 · 건너뛰기 · 취소, UTF-8 / CP949 / CP437 · NFC / NFD 후보 자동 시도
- Zip64 읽기 · 쓰기 (4 GiB 초과 항목, 65,535개 초과 항목)
- 한국어 파일 이름 — CP949 읽기 · 쓰기, 유니코드 경로 extra field(0x7075), NFC 정규화
- 압축 방식 · 암호화 방식을 공개 프로토콜로 확장
- 진행률(`Progress`) · 취소 · 메모리 입출력

설계 문서: [docs/DESIGN.md](docs/DESIGN.md)

## 요구 사항

- iOS 15+ / macOS 12+
- Swift 6 (Xcode 16+)

## 설치

```swift
.package(url: "https://github.com/eren0315/Satchel.git", exact: "0.1.0")
```

`1.0.0` 전까지는 마이너 버전에서 API 가 바뀔 수 있어 `exact:` 고정을 권합니다.

## 사용법

### 만들기

```swift
import Satchel

try Zip.create(at: archiveURL, from: [folderURL, fileURL])

var options = WriteOptions()
options.encryption = .aes(.bits256)
options.password = Password("비밀번호")
try Zip.create(at: archiveURL, from: [folderURL], options: options)
```

### 풀기

```swift
try Zip.extract(archiveURL, to: destinationURL)

var options = ExtractOptions()
options.password = Password("비밀번호")
try Zip.extract(archiveURL, to: destinationURL, options: options)
```

실패하면 `destinationURL` 은 호출 전 상태 그대로이고, 임시 파일도 남지 않습니다.

### 비밀번호를 물어 가며 풀기

```swift
let provider = ClosurePasswordProvider { request in
    // request.entry.path · request.attempt · request.reason(.required / .wrongPassword)
    guard let typed = await askUser(for: request) else { return .cancel }
    return .password(Password(typed))
}
let result = try await Zip.extract(archiveURL, to: destinationURL, passwordProvider: provider)
print(result.extracted.count, result.skipped.count)
```

한 번 맞은 비밀번호는 다음 항목에서 먼저 시도하므로, 비밀번호 하나로 잠긴 zip 은 한 번만 묻습니다.

### 항목 단위

```swift
let reader = try ArchiveReader(url: archiveURL)
for entry in reader.entries {
    print(entry.path, entry.uncompressedSize, entry.encryption as Any)
}
let data = try reader.data(for: reader.entries[0], password: Password("비밀번호"))
let check = try reader.verify(Password("비밀번호"), for: reader.entries[0])   // .likelyCorrect / .wrong

let writer = ArchiveWriter()                        // 메모리
try writer.add(Data("hello".utf8), as: "hello.txt")
let zipData = try writer.finishData()
```

### 확장

```swift
struct MyCodec: CompressionCodec { /* methodID · makeCompressor · makeDecompressor */ }
struct MyScheme: EncryptionScheme { /* matches · makeDecryptor · makeEncryptor … */ }

var read = ReadOptions()
read.registry = ZipRegistry.standard.registering(MyCodec()).registering(MyScheme())
```

## 보안 메모

- **ZipCrypto 는 깨진 암호입니다.** 알려진 공격으로 비밀번호 없이 풀립니다. `.legacyZipCrypto` 는 운영체제 기본 도구로 열어야 할 때만 쓰세요.
- 해제 기본 상한: 총 8 GiB(메모리로 푸는 `data(for:)` 는 512 MiB), 항목별 압축 비율 1,000:1, 항목 100,000개, 경로 깊이 256 (`ExtractLimits` · `ReadOptions` 로 조절).
- 외부 zip 의 권한은 rwx 만 복원하고 group/other 쓰기와 setuid 류는 지웁니다. 대상 폴더 안의 기존 심볼릭 링크를 거쳐 쓰지 않습니다.
- `Password` 는 `description` · `dump()` 에 내용을 드러내지 않습니다. Swift `String` 원본은 지울 수 없으니 민감하면 `Password(bytes:)` 를 쓰세요.
- CP949 비밀번호로 만든 zip 은 Satchel · 한국어 Windows 도구와만 호환이 보장됩니다.

## 샘플 앱

`Example/SatchelExample.swiftpm` 을 Xcode 로 열면 iOS 앱으로 실행됩니다 — zip 열기(항목 목록 · 비밀번호 입력 창 · 진행률 · 취소)와 만들기(압축 · 암호화 · 이름 인코딩 · Zip64).
샘플만 **iOS 16+** 입니다(`NavigationStack` · `ShareLink`). 실행 방법 · 테스트용 zip · 버전 이유는 [Example/README.md](Example/README.md).

## 테스트

```bash
swift test
```

픽스처는 macOS 기본 도구(`bsdtar` · `zip` · `unzip` · `ditto`)와 `python3` 로 테스트 중에 만듭니다. AES 는 libarchive(`bsdtar`)와 교차 검증합니다. 4 GiB 초과 테스트는 `SATCHEL_LARGE_TESTS=1 swift test -c release`.

## 라이선스

[0BSD](LICENSE) — 조건 없이 사용 · 수정 · 배포할 수 있습니다. 저작권 표시도 필요 없습니다.
