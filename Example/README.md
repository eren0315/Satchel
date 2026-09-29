# Satchel sample app

**English** · [한국어](README.ko.md)

An iOS app for trying out Satchel's features by hand.

- **Open**: list a zip's entries (encryption · Zip64 · size) → extract everything, with a password prompt (retry · skip · cancel all), progress and cancellation
- **Create**: pick files → compression · encryption (AES-128/192/256) · filename encoding (UTF-8 / CP949) · Zip64 → share sheet

## Running

1. If the library folder (`Satchel/`) is open in Xcode, **close it first** — the sample references the same package by local path (`../..`), and having it open in another window can keep Xcode from resolving the dependency.
2. Open `SatchelExample.swiftpm` in Xcode (double-clicking it in Finder also works).

   ```bash
   open -a Xcode Example/SatchelExample.swiftpm
   ```

3. Choose the `SatchelExample` scheme and an iPhone simulator (iOS 16+), then press ⌘R.
   If the scheme doesn't show up, use File → Packages → Reset Package Caches.

The simulator needs no code-signing setup.

## Zips to try

Drag a zip onto the simulator window to save it to the Files app, then pick it with "zip 파일 고르기" (Choose a zip file).

```bash
cd /tmp && echo "hello satchel" > a.txt \
  && bsdtar --format zip --options zip:encryption=aes256 --passphrase 1234 -cf aes.zip a.txt \
  && zip -q -P 1234 zipcrypto.zip a.txt
```

- `aes.zip`: password `1234`. A wrong password asks again ("비밀번호가 틀렸습니다 (2번째)" — wrong password, 2nd attempt).
- `zipcrypto.zip`: ZipCrypto (traditional zip encryption) is **not supported** — it shows up as "zipcrypto · 미지원" (unsupported) in the list, and extracting it explains why.

The sample's UI text is in Korean.

## Why the sample targets iOS 16

**It is one step above the library (iOS 15+)** because the sample uses two SwiftUI APIs that are available from iOS 16.

| API | Where | Minimum |
| --- | --- | --- |
| `NavigationStack` | both the Open and Create tabs | iOS 16 |
| `ShareLink` | Create tab — sharing the created zip | iOS 16 |

- The sample doesn't ship inside any app, so it favors shorter code. **The library itself works on iOS 15** (verified by `swift test` and an iOS device build).
- To run it on an iOS 15 device, replace `NavigationStack` with `NavigationView` (`.navigationViewStyle(.stack)`) and `ShareLink` with a `UIActivityViewController` share sheet.
- The password prompt (`SecureField` inside an `alert`), `fileImporter` and `ProgressView(Progress)` all work on iOS 15.

## ⚠️ Running on a device

When you choose a team under Signing & Capabilities, Xcode **writes `teamIdentifier: "…"` into `Package.swift`.**
This is a public repository — **use a personal team and don't commit that line.** (Change `bundleIdentifier` too if you need to.)
