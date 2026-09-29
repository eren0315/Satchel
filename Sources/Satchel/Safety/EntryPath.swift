import Foundation

/// 항목 이름 검증·정규화. 하나라도 걸리면 zip 전체를 풀지 않는다.
enum EntryPath {
    /// 구성 요소 수 상한. 이보다 깊으면 대부분의 파일 시스템에서 어차피 만들 수 없고(PATH_MAX 1024),
    /// 사전 점검의 상위 경로 키 계산이 깊이의 제곱으로 커진다.
    static let maxComponents = 256
    static let maxLength = 4096

    /// `\` → `/`, `.`·빈 구성 요소 제거. 빈 이름 · 제어 문자 · 절대 경로 · 드라이브 문자 · `..` 는 거부.
    static func components(of path: String) throws -> [String] {
        let unified = path.replacingOccurrences(of: "\\", with: "/")
        guard !unified.isEmpty else { throw ZipError.unsafeEntryPath(path, reason: "empty name") }
        guard unified.utf8.count <= maxLength else { throw ZipError.unsafeEntryPath(String(path.prefix(64)) + "…", reason: "path too long") }
        if unified.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) {
            throw ZipError.unsafeEntryPath(path, reason: "control character")
        }
        if unified.hasPrefix("/") { throw ZipError.unsafeEntryPath(path, reason: "absolute path") }
        let scalars = Array(unified.unicodeScalars.prefix(2))
        if scalars.count == 2, scalars[1] == ":", CharacterSet.letters.contains(scalars[0]) {
            throw ZipError.unsafeEntryPath(path, reason: "drive letter")
        }
        var result: [String] = []
        for part in unified.split(separator: "/", omittingEmptySubsequences: true) {
            if part == "." { continue }
            if part == ".." { throw ZipError.unsafeEntryPath(path, reason: "parent directory reference") }
            result.append(String(part))
        }
        guard !result.isEmpty else { throw ZipError.unsafeEntryPath(path, reason: "empty name") }
        guard result.count <= maxComponents else { throw ZipError.unsafeEntryPath(String(path.prefix(64)) + "…", reason: "path too deep") }
        return result
    }

    /// 구성 요소를 base 아래 URL 로. 최종 경로가 base 안인지 다시 확인한다 (규칙의 안전망).
    static func resolve(_ components: [String], in base: URL) throws -> URL {
        var url = base
        for c in components { url.appendPathComponent(c) }
        let basePath = base.standardizedFileURL.path
        let resolved = url.standardizedFileURL.path
        guard resolved.hasPrefix(basePath.hasSuffix("/") ? basePath : basePath + "/") else {
            throw ZipError.unsafeEntryPath(components.joined(separator: "/"), reason: "escapes destination")
        }
        return url
    }
}
