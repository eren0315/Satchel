import Foundation

/// zip 안의 항목 하나 (목차 기준).
public struct Entry: Sendable, Hashable {
    public enum Kind: Sendable, Hashable { case file, directory, symlink }

    /// 해석한 이름. 구분자는 `/`, 폴더는 `/` 로 끝난다.
    public let path: String
    /// 원본 이름 바이트.
    public let rawPath: [UInt8]
    public let kind: Kind
    public let uncompressedSize: UInt64
    public let compressedSize: UInt64
    /// AE-2 처럼 CRC 를 저장하지 않는 방식이면 nil.
    public let crc32: UInt32?
    public let modificationDate: Date?
    /// 실제 압축 방식 번호 (AES 항목도 99 가 아닌 실제 방식).
    public let compressionMethodID: UInt16
    /// nil = 암호화 안 됨.
    public let encryption: EncryptionIdentifier?
    public let isZip64: Bool
    public let unixPermissions: UInt16?
    public let extraFields: [ExtraField]

    /// 이 zip 안에서의 순서 (0부터).
    public let index: Int

    let nameDecodingFailed: Bool

    public var isEncrypted: Bool { encryption != nil }
}

public struct ExtractResult: Sendable {
    public let extracted: [Entry]
    /// 비밀번호 제공자가 `.skipEntry` 로 건너뛴 항목.
    public let skipped: [Entry]
}

public struct CreateResult: Sendable {
    public let entries: [Entry]
    public let usedZip64: Bool
}

/// 등록된 스킴이 없을 때 목록에 보여 줄 이름 (풀 수는 없다).
enum EncryptionName {
    static let pkwareStrong = EncryptionIdentifier(rawValue: "pkware-strong")
    /// 전통 PKWARE 암호 — 지원하지 않는다 (깨진 암호).
    static let zipCrypto = EncryptionIdentifier(rawValue: "zipcrypto")
    static let unknown = EncryptionIdentifier(rawValue: "unknown")
}

extension Entry {
    static func make(header h: EntryHeader, index: Int, encoding: FilenameEncoding, registry: ZipRegistry) -> Entry {
        let (decoded, failed) = decodeName(h, encoding: encoding)
        let path = decoded.replacingOccurrences(of: "\\", with: "/")

        let isUnix = h.versionMadeBy >> 8 == 3
        let mode = UInt16(truncatingIfNeeded: h.externalAttributes >> 16)
        let fileType = mode & 0o170000
        let kind: Kind
        if isUnix && fileType == 0o120000 {
            kind = .symlink
        } else if path.hasSuffix("/") || (isUnix && fileType == 0o040000) || (!isUnix && h.externalAttributes & 0x10 != 0) {
            kind = .directory
        } else {
            kind = .file
        }

        let scheme = h.isEncrypted ? registry.scheme(matching: h) : nil
        let encryption: EncryptionIdentifier?
        if !h.isEncrypted {
            encryption = nil
        } else if let scheme {
            encryption = scheme.identifier
        } else if h.generalPurposeFlags & GeneralPurposeFlag.strongEncryption != 0 {
            encryption = EncryptionName.pkwareStrong
        } else if h.compressionMethodID != WinZipAESScheme.methodID {
            encryption = EncryptionName.zipCrypto
        } else {
            encryption = EncryptionName.unknown
        }

        let date = h.extraFields.lazy.compactMap(\.extendedTimestampModificationDate).first
            ?? DOSDateTime.decode(time: h.dosTime, date: h.dosDate)

        let crcAbsent = !(scheme?.storesCRC(for: h) ?? true)

        return Entry(
            path: path,
            rawPath: h.rawName,
            kind: kind,
            uncompressedSize: h.uncompressedSize,
            compressedSize: h.compressedSize,
            crc32: crcAbsent ? nil : h.crc32,
            modificationDate: date,
            compressionMethodID: scheme?.actualCompressionMethodID(for: h) ?? h.compressionMethodID,
            encryption: encryption,
            isZip64: h.usesZip64,
            unixPermissions: isUnix ? mode & 0o7777 : nil,
            extraFields: h.extraFields,
            index: index,
            nameDecodingFailed: failed)
    }

    private static func decodeName(_ h: EntryHeader, encoding: FilenameEncoding) -> (String, Bool) {
        let raw = h.rawName
        if let forced = encoding.stringEncoding {
            if let s = TextCodec.decode(raw, forced) { return (s, false) }
            return (String(decoding: raw, as: UTF8.self), true)
        }
        if h.generalPurposeFlags & GeneralPurposeFlag.utf8 != 0, let s = String(bytes: raw, encoding: .utf8) {
            return (s, false)
        }
        if let s = h.extraFields.lazy.compactMap({ $0.unicodePathName(matching: raw) }).first {
            return (s, false)
        }
        if let s = String(bytes: raw, encoding: .utf8) { return (s, false) }
        if let s = TextCodec.decode(raw, TextCodec.cp949) { return (s, false) }
        if let s = TextCodec.decode(raw, TextCodec.cp437) { return (s, false) }
        return (String(decoding: raw, as: UTF8.self), true)
    }
}
