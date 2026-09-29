# Satchel 샘플 앱

Satchel 의 기능을 직접 눌러 보는 iOS 앱입니다.

- **열기**: zip 항목 목록(암호화 방식 · Zip64 · 크기) → 전부 풀기, 비밀번호 입력 창(재시도 · 건너뛰기 · 전체 취소), 진행률 · 취소
- **만들기**: 파일 고르기 → 압축 방식 · 암호화(AES-128/192/256) · 파일 이름 인코딩(UTF-8 / CP949) · Zip64 → 공유 시트

## 실행

1. 라이브러리 폴더(`Satchel/`)가 Xcode 에 열려 있으면 **먼저 닫습니다** — 샘플은 같은 패키지를 로컬 경로(`../..`)로 참조하므로, 다른 창에 열려 있으면 의존성을 제대로 잡지 못할 수 있습니다.
2. `SatchelExample.swiftpm` 을 Xcode 로 엽니다 (Finder 에서 더블클릭해도 됩니다).

   ```bash
   open -a Xcode Example/SatchelExample.swiftpm
   ```

3. 스킴 `SatchelExample` · iPhone 시뮬레이터(iOS 16+)를 고르고 ⌘R.
   스킴이 안 보이면 File → Packages → Reset Package Caches.

시뮬레이터는 서명 설정이 필요 없습니다.

## 풀어 볼 zip

시뮬레이터 창에 zip 을 끌어다 놓으면 파일 앱에 저장되고, "zip 파일 고르기"에서 고를 수 있습니다.

```bash
cd /tmp && echo "hello satchel" > a.txt \
  && bsdtar --format zip --options zip:encryption=aes256 --passphrase 1234 -cf aes.zip a.txt \
  && zip -q -P 1234 zipcrypto.zip a.txt
```

- `aes.zip`: 비밀번호 `1234`. 틀리게 넣으면 "비밀번호가 틀렸습니다 (2번째)" 로 다시 묻습니다.
- `zipcrypto.zip`: ZipCrypto(전통 zip 암호)는 **지원하지 않습니다** — 목록에 "zipcrypto · 미지원" 으로 보이고, 풀면 이유를 알려 줍니다.

## 최소 버전이 iOS 16 인 이유

**라이브러리(iOS 15+)보다 한 단계 높습니다.** 샘플에서 iOS 16 부터 쓸 수 있는 SwiftUI API 두 개를 썼기 때문입니다.

| API | 쓰는 곳 | 최소 버전 |
| --- | --- | --- |
| `NavigationStack` | 열기 · 만들기 두 탭 | iOS 16 |
| `ShareLink` | 만들기 탭 — 만든 zip 공유 | iOS 16 |

- 샘플은 앱에 들어가지 않으니 코드를 짧게 두는 쪽을 택했습니다. **라이브러리 자체는 iOS 15 에서 동작합니다** (`swift test` · iOS 기기 빌드로 확인).
- iOS 15 기기에서 돌려 봐야 하면 `NavigationStack` → `NavigationView`(`.navigationViewStyle(.stack)`), `ShareLink` → `UIActivityViewController` 공유 시트로 바꾸면 됩니다.
- 비밀번호 창(`alert` 안의 `SecureField`) · `fileImporter` · `ProgressView(Progress)` 는 iOS 15 에서도 됩니다.

## ⚠️ 실기기에서 돌릴 때

Signing & Capabilities 에서 팀을 고르면 Xcode 가 `Package.swift` 에 `teamIdentifier: "…"` 를 **직접 써 넣습니다.**
공개 저장소이므로 **개인 팀을 쓰고, 이 한 줄은 커밋하지 마세요.** (`bundleIdentifier` 도 필요하면 각자 바꿉니다.)
