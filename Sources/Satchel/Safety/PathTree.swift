import Foundation

/// 항목 경로 트리 — 중복 · 파일/폴더 이름 충돌을 경로 길이에 비례하는 비용으로 판정한다.
/// 비교 기준은 구성 요소별 NFC + 대소문자 무시 (macOS 기본 볼륨과 같은 기준).
final class PathTree {
    private final class Node {
        enum Kind { case implicitDirectory, directory, file }
        var kind: Kind
        var children: [String: Node] = [:]
        init(_ kind: Kind) { self.kind = kind }
    }

    private let root = Node(.implicitDirectory)

    static func normalize(_ component: String) -> String {
        component.precomposedStringWithCanonicalMapping.lowercased()
    }

    /// 넣을 수 있는지만 본다 (트리를 바꾸지 않는다).
    func validate(_ components: [String], isDirectory: Bool, path: String) throws {
        try walk(components, isDirectory: isDirectory, path: path, commit: false)
    }

    /// 검사하고 넣는다.
    func insert(_ components: [String], isDirectory: Bool, path: String) throws {
        try walk(components, isDirectory: isDirectory, path: path, commit: false)
        try walk(components, isDirectory: isDirectory, path: path, commit: true)
    }

    private func walk(_ components: [String], isDirectory: Bool, path: String, commit: Bool) throws {
        var node = root
        for (i, component) in components.enumerated() {
            let key = Self.normalize(component)
            let last = i == components.count - 1
            guard let child = node.children[key] else {
                guard commit else { return }   // 여기서부터는 새 경로 — 충돌 없음
                let created = Node(last ? (isDirectory ? .directory : .file) : .implicitDirectory)
                node.children[key] = created
                node = created
                continue
            }
            if !last {
                if child.kind == .file { throw ZipError.unsafeEntryPath(path, reason: "file and directory share a name") }
                node = child
                continue
            }
            switch (child.kind, isDirectory) {
            case (.implicitDirectory, true):
                if commit { child.kind = .directory }
            case (.directory, true), (.file, false):
                throw ZipError.unsafeEntryPath(path, reason: "duplicate entry")
            case (.implicitDirectory, false), (.directory, false), (.file, true):
                throw ZipError.unsafeEntryPath(path, reason: "file and directory share a name")
            }
        }
    }
}
