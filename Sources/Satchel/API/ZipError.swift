/// Satchel 이 던지는 에러. 문자열에는 항목 이름과 이유만 담는다 — 비밀번호·키·복호화된 내용은 절대 넣지 않는다.
/// 파일 입출력 에러(`CocoaError`, POSIX 에러)는 감싸지 않고 그대로 던진다.
public enum ZipError: Error, Sendable, Equatable {
    /// 암호화된 항목인데 비밀번호가 없다.
    case passwordRequired(entry: String)
    /// 비밀번호가 틀렸다.
    case wrongPassword(entry: String)
    /// 구조 손상 · CRC 불일치 · HMAC 불일치 · 선언 크기 초과 등.
    case corrupted(entry: String?, reason: String)
    /// 경로 탈출 · 절대 경로 · 중복 이름 · 심볼릭 링크 등 안전하지 않은 항목.
    case unsafeEntryPath(String, reason: String)
    /// `ReadOptions` / `ExtractLimits` 상한 초과.
    case limitExceeded(String)
    /// 지원하지 않는 기능 (분할 zip, PKWARE Strong Encryption, 등록되지 않은 압축·암호화 방식 등).
    case unsupported(String)
    /// `ExtractOptions.allowedEncryption` 에 없는 암호화 방식.
    case disallowedEncryption(EncryptionIdentifier)
    /// 만들려는 파일·폴더가 이미 있다.
    case destinationExists(String)
    /// 지정한 인코딩으로 이름을 표현하거나 해석할 수 없다.
    case filenameEncodingFailed(String)
    /// 취소됐다 (`Progress.cancel()`, Task 취소, 비밀번호 제공자의 `.cancel`).
    case cancelled
}
