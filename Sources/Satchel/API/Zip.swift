import Foundation

/// 간편 함수.
public enum Zip {
    /// `items`(파일·폴더)를 묶어 `archiveURL` 에 zip 을 만든다.
    /// 폴더는 하위 전체를 넣고, 항목 이름은 각 item 의 부모 폴더 기준 상대 경로다(폴더 이름 포함).
    @discardableResult
    public static func create(at archiveURL: URL, from items: [URL], options: WriteOptions = .init()) throws -> CreateResult {
        let writer = try ArchiveWriter(url: archiveURL, options: options)
        for item in items {
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: item.path, isDirectory: &isDirectory)
            if isDirectory.boolValue {
                try writer.addDirectory(at: item)
            } else {
                try writer.addFile(at: item)
            }
        }
        return try writer.finish()
    }

    /// 고정 비밀번호(또는 없음)로 전부 푼다. 전부 성공해야 결과가 나타난다.
    @discardableResult
    public static func extract(_ archiveURL: URL, to destinationURL: URL,
                               readOptions: ReadOptions = .init(),
                               options: ExtractOptions = .init()) throws -> ExtractResult {
        try ArchiveReader(url: archiveURL, options: readOptions).extractAll(to: destinationURL, options: options)
    }

    /// 비밀번호 제공자에게 항목마다 물어 가며 푼다. Task 취소를 따른다.
    @discardableResult
    public static func extract(_ archiveURL: URL, to destinationURL: URL,
                               readOptions: ReadOptions = .init(),
                               options: ExtractOptions = .init(),
                               passwordProvider: any PasswordProvider) async throws -> ExtractResult {
        try await ArchiveReader(url: archiveURL, options: readOptions)
            .extractAll(to: destinationURL, options: options, passwordProvider: passwordProvider)
    }
}
