# Satchel

**English** · [한국어](README.ko.md)

A pure Swift zip library — **compress · extract · encryption (WinZip AES) · Zip64 · CP949**.
No external dependencies: only `Foundation` · `Compression` · `CommonCrypto` · `Security`.

- Extracts untrusted zips **safely** — blocks path traversal, symbolic links, zip bombs and integrity violations; extraction is **all-or-nothing**
- WinZip AES 128/192/256 (AES-256 · AE-2 by default when creating) — all cryptography goes through the OS `CommonCrypto`
- Password provider — per-entry passwords, retry, skip, cancel; tries UTF-8 / CP949 / CP437 and NFC / NFD candidates automatically
- Zip64 read and write (entries over 4 GiB, more than 65,535 entries)
- Korean filenames — CP949 read and write, Unicode Path extra field (0x7075), NFC normalization
- Pluggable compression and encryption through public protocols
- Progress (`Progress`) · cancellation · in-memory I/O

Design document (Korean): [docs/DESIGN.md](docs/DESIGN.md)

## Requirements

- iOS 15+ / macOS 12+
- Swift 6 (Xcode 16+)

## Installation

```swift
.package(url: "https://github.com/eren0315/Satchel.git", exact: "0.1.0")
```

Until `1.0.0`, the API may change between minor versions, so pinning with `exact:` is recommended.

## Usage

### Create

```swift
import Satchel

try Zip.create(at: archiveURL, from: [folderURL, fileURL])

var options = WriteOptions()
options.encryption = .aes(.bits256)
options.password = Password("secret")
try Zip.create(at: archiveURL, from: [folderURL], options: options)
```

### Extract

```swift
try Zip.extract(archiveURL, to: destinationURL)

var options = ExtractOptions()
options.password = Password("secret")
try Zip.extract(archiveURL, to: destinationURL, options: options)
```

If extraction fails, `destinationURL` is left exactly as it was before the call, and no temporary files remain.

### Extract while asking for passwords

```swift
let provider = ClosurePasswordProvider { request in
    // request.entry.path · request.attempt · request.reason (.required / .wrongPassword)
    guard let typed = await askUser(for: request) else { return .cancel }
    return .password(Password(typed))
}
let result = try await Zip.extract(archiveURL, to: destinationURL, passwordProvider: provider)
print(result.extracted.count, result.skipped.count)
```

A password that worked once is tried first for the following entries, so a zip locked with a single password asks only once.

### Per-entry access

```swift
let reader = try ArchiveReader(url: archiveURL)
for entry in reader.entries {
    print(entry.path, entry.uncompressedSize, entry.encryption as Any)
}
let data = try reader.data(for: reader.entries[0], password: Password("secret"))
let check = try reader.verify(Password("secret"), for: reader.entries[0])   // .likelyCorrect / .wrong

let writer = ArchiveWriter()                        // in memory
try writer.add(Data("hello".utf8), as: "hello.txt")
let zipData = try writer.finishData()
```

### Extending

```swift
struct MyCodec: CompressionCodec { /* methodID · makeCompressor · makeDecompressor */ }
struct MyScheme: EncryptionScheme { /* matches · makeDecryptor · makeEncryptor … */ }

var read = ReadOptions()
read.registry = ZipRegistry.standard.registering(MyCodec()).registering(MyScheme())
```

## Security notes

- **ZipCrypto (traditional zip encryption) is not supported.** ZipCrypto-locked zips fail with `ZipError.unsupported`.
- Default extraction limits: 8 GiB in total (512 MiB for in-memory `data(for:)`), a 1,000:1 compression ratio per entry, 100,000 entries, and a path depth of 256 (adjust with `ExtractLimits` · `ReadOptions`).
- Permissions from an untrusted zip are restored as rwx bits only; group/other write bits and setuid-style bits are removed. Extraction never writes through a symbolic link that already exists in the destination.
- `Password` never reveals its contents through `description` or `dump()`. A Swift `String` cannot be wiped from memory, so use `Password(bytes:)` when that matters.

## Sample app

Open `Example/SatchelExample.swiftpm` in Xcode to run it as an iOS app — open a zip (entry list · password prompt · progress · cancel) and create one (compression · encryption · filename encoding · Zip64).
Only the sample requires **iOS 16+** (`NavigationStack` · `ShareLink`). See [Example/README.md](Example/README.md) for how to run it, test zips, and why it targets iOS 16.

## Tests

```bash
swift test
```

Fixtures are generated during the tests with built-in macOS tools (`bsdtar` · `zip` · `unzip` · `ditto`) and `python3`. AES is cross-checked against libarchive (`bsdtar`). Run the over-4-GiB test with `SATCHEL_LARGE_TESTS=1 swift test -c release`.

## License

[0BSD](LICENSE) — use, modify and distribute without any conditions. No attribution required.
