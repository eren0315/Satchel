# Satchel

순수 Swift zip 라이브러리 — **압축 · 해제 · 암호화(WinZip AES / ZipCrypto) · Zip64 · CP949**.

> 🚧 **설계 단계 (0.x)** — 아직 사용할 수 있는 코드가 없습니다. 설계는 [docs/DESIGN.md](docs/DESIGN.md) 를 보세요.

## 특징 (계획)

- 외부 의존성 없음 — `Foundation` · `Compression` · `CommonCrypto` · `Security` 만 사용
- 외부에서 받은 zip 을 안전하게 해제 — 경로 탈출 · 심볼릭 링크 · 압축 폭탄 차단, 전부 되거나 아무것도 남지 않는 해제
- WinZip AES 128/192/256 (생성 기본값 AES-256), ZipCrypto 해제 (생성은 명시적으로 켤 때만)
- 비밀번호 제공자 — 항목별 비밀번호 · 재시도 · 건너뛰기 · 취소, UTF-8 / CP949 / CP437 후보 자동 시도
- Zip64 읽기 · 쓰기
- 한국어 파일 이름 — CP949 읽기 · 쓰기, 유니코드 경로 extra field, NFC 정규화
- 압축 방식 · 암호화 방식을 공개 프로토콜로 확장

## 요구 사항 (계획)

- iOS 13+ / macOS 10.15+
- Swift 6 (Xcode 16+)

## 설치 (0.1.0 이후)

```swift
.package(url: "https://github.com/eren0315/Satchel.git", exact: "0.1.0")
```

## 라이선스

[0BSD](LICENSE) — 조건 없이 사용 · 수정 · 배포할 수 있습니다. 저작권 표시도 필요 없습니다.
