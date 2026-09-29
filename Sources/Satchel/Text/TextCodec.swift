import Foundation

enum TextCodec {
    static let cp949 = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(
        CFStringEncoding(CFStringEncodings.dosKorean.rawValue)))
    static let cp437 = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(
        CFStringEncoding(CFStringEncodings.dosLatinUS.rawValue)))

    static func isASCII(_ bytes: [UInt8]) -> Bool { bytes.allSatisfy { $0 < 0x80 } }

    static func decode(_ bytes: [UInt8], _ encoding: String.Encoding) -> String? {
        if bytes.isEmpty { return "" }
        if isASCII(bytes) { return String(decoding: bytes, as: UTF8.self) }
        return String(bytes: bytes, encoding: encoding)
    }

    static func encode(_ string: String, _ encoding: String.Encoding) -> [UInt8]? {
        if encoding == .utf8 { return Array(string.utf8) }
        guard let data = string.data(using: encoding, allowLossyConversion: false) else { return nil }
        return [UInt8](data)
    }
}

extension FilenameEncoding {
    var stringEncoding: String.Encoding? {
        switch self {
        case .automatic: return nil
        case .utf8: return .utf8
        case .cp949: return TextCodec.cp949
        case .cp437: return TextCodec.cp437
        case .custom(let e): return e
        }
    }
}

extension PasswordEncoding {
    var stringEncoding: String.Encoding {
        switch self {
        case .utf8: return .utf8
        case .cp949: return TextCodec.cp949
        case .cp437: return TextCodec.cp437
        case .custom(let e): return e
        }
    }
}
