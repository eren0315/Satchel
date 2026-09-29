import Foundation
import Satchel

/// 파일 선택기가 준 URL(보안 범위)을 앱 임시 폴더로 복사한다.
func copyToTemporary(_ picked: URL) throws -> URL {
    let accessing = picked.startAccessingSecurityScopedResource()
    defer { if accessing { picked.stopAccessingSecurityScopedResource() } }
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    let local = folder.appendingPathComponent(picked.lastPathComponent)
    try FileManager.default.copyItem(at: picked, to: local)
    return local
}

func documentsDirectory() -> URL {
    FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
}

func timestamp() -> String {
    let f = DateFormatter()
    f.dateFormat = "yyyyMMdd-HHmmss"
    return f.string(from: Date())
}

func describe(_ error: Error) -> String {
    guard let e = error as? ZipError else { return error.localizedDescription }
    switch e {
    case .passwordRequired(let entry): return "비밀번호가 필요합니다: \(entry)"
    case .wrongPassword(let entry): return "비밀번호가 틀렸습니다: \(entry)"
    case .corrupted(let entry, let reason): return "손상된 파일\(entry.map { " (\($0))" } ?? ""): \(reason)"
    case .unsafeEntryPath(let path, let reason): return "안전하지 않은 항목 \(path): \(reason)"
    case .limitExceeded(let what): return "상한 초과: \(what)"
    case .unsupported(let what): return "지원하지 않음: \(what)"
    case .disallowedEncryption(let id): return "허용하지 않은 암호화: \(id.rawValue)"
    case .destinationExists(let path): return "이미 있습니다: \(path)"
    case .filenameEncodingFailed(let name): return "이름을 인코딩할 수 없습니다: \(name)"
    case .cancelled: return "취소했습니다"
    }
}
