import Foundation

/// 비밀번호. `description` · `debugDescription` · `dump()` 어디에도 내용이 나오지 않는다.
public struct Password: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    final class Storage: @unchecked Sendable {   // 생성 후 불변 — deinit 에서만 지운다
        private(set) var candidates: [[UInt8]]
        private(set) var writeBytes: [UInt8]?

        init(candidates: [[UInt8]], writeBytes: [UInt8]?) {
            self.candidates = candidates
            self.writeBytes = writeBytes
        }

        deinit {
            for i in candidates.indices { Storage.wipe(&candidates[i]) }
            if writeBytes != nil { Storage.wipe(&writeBytes!) }
        }

        private static func wipe(_ bytes: inout [UInt8]) {
            bytes.withUnsafeMutableBytes { buffer in
                if let base = buffer.baseAddress { memset_s(base, buffer.count, 0, buffer.count) }
            }
        }
    }

    let storage: Storage

    /// 문자열 비밀번호.
    /// - 해제: `encodings` 순서로, 각 인코딩마다 NFC · NFD 형태의 바이트 후보를 만들어 차례로 시도한다
    ///   (같은 바이트는 합치고, 표현할 수 없는 인코딩은 건너뛴다). macOS 도구는 인수를 NFD 로 넘기기도 한다.
    /// - 생성: `encodings` 의 첫 번째로, NFC 형태를 쓴다.
    /// - Swift `String` 원본은 지울 수 없다. 메모리 노출이 민감하면 `init(bytes:)` 를 쓴다.
    public init(_ string: String, encodings: [PasswordEncoding] = [.utf8, .cp949, .cp437]) {
        var seen = Set<[UInt8]>()
        var candidates: [[UInt8]] = []
        let nfc = string.precomposedStringWithCanonicalMapping
        let forms = [nfc, string.decomposedStringWithCanonicalMapping]
        for e in encodings {
            for form in forms {
                guard let b = TextCodec.encode(form, e.stringEncoding), seen.insert(b).inserted else { continue }
                candidates.append(b)
            }
        }
        let write = encodings.first.flatMap { TextCodec.encode(nfc, $0.stringEncoding) }
        storage = Storage(candidates: candidates, writeBytes: write)
    }

    /// 바이트 그대로 (Keychain 등에서 꺼낸 값).
    public init(bytes: [UInt8]) {
        storage = Storage(candidates: [bytes], writeBytes: bytes)
    }

    var candidates: [[UInt8]] { storage.candidates }
    var bytesForWriting: [UInt8]? { storage.writeBytes }

    public var description: String { "Password(•••)" }
    public var debugDescription: String { "Password(•••)" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

public enum PasswordEncoding: Sendable, Hashable {
    case utf8
    /// 한국어 Windows 도구 호환.
    case cp949
    case cp437
    case custom(String.Encoding)
}

/// 항목마다 비밀번호를 묻는 대상. UI 를 띄우는 구현은 스스로 `@MainActor` 로 넘어간다.
public protocol PasswordProvider: Sendable {
    func password(for request: PasswordRequest) async -> PasswordResponse
}

public struct PasswordRequest: Sendable {
    public enum Reason: Sendable, Hashable {
        /// 이 항목에서 처음 묻는다.
        case required
        /// 직전에 받은 비밀번호가 틀렸다.
        case wrongPassword
    }

    public let entry: Entry
    /// 1부터. 틀릴 때마다 올라간다.
    public let attempt: Int
    public let reason: Reason
}

public enum PasswordResponse: Sendable {
    case password(Password)
    /// 여러 개를 차례로 시도한다.
    case passwords([Password])
    /// 이 항목만 빼고 계속한다.
    case skipEntry
    /// 전체를 중단한다 → `ZipError.cancelled`.
    case cancel
}

public enum PasswordCheck: Sendable, Hashable {
    /// 무결성(HMAC · CRC)까지 확인했다.
    case correct
    /// 빠른 확인(AES 2바이트 · ZipCrypto 1바이트)만 통과했다.
    case likelyCorrect
    case wrong
}

/// 클로저로 만드는 비밀번호 제공자.
public struct ClosurePasswordProvider: PasswordProvider {
    let body: @Sendable (PasswordRequest) async -> PasswordResponse

    public init(_ body: @escaping @Sendable (PasswordRequest) async -> PasswordResponse) {
        self.body = body
    }

    public func password(for request: PasswordRequest) async -> PasswordResponse {
        await body(request)
    }
}
