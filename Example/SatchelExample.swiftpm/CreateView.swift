import Satchel
import SwiftUI
import UniformTypeIdentifiers

struct CreateView: View {
    enum Encryption: String, CaseIterable, Identifiable {
        case none = "없음"
        case aes256 = "AES-256"
        case aes192 = "AES-192"
        case aes128 = "AES-128"
        var id: Self { self }

        var method: EncryptionMethod {
            switch self {
            case .none: .none
            case .aes256: .aes(.bits256)
            case .aes192: .aes(.bits192)
            case .aes128: .aes(.bits128)
            }
        }
    }

    enum NameEncoding: String, CaseIterable, Identifiable {
        case utf8 = "UTF-8"
        case cp949 = "CP949 (옛 Windows 호환)"
        var id: Self { self }
    }

    @State private var importing = false
    @State private var files: [URL] = []
    @State private var compression = true
    @State private var encryption = Encryption.aes256
    @State private var password = ""
    @State private var nameEncoding = NameEncoding.utf8
    @State private var zip64 = false
    @State private var created: URL?
    @State private var summary: String?
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("파일") {
                    Button("파일 고르기") { importing = true }
                    ForEach(files, id: \.self) { Text($0.lastPathComponent).font(.footnote.monospaced()) }
                }

                Section("설정") {
                    Toggle("DEFLATE 압축", isOn: $compression)
                    Picker("암호화", selection: $encryption) {
                        ForEach(Encryption.allCases) { Text($0.rawValue).tag($0) }
                    }
                    if encryption != .none {
                        SecureField("비밀번호", text: $password)
                    }
                    Picker("파일 이름", selection: $nameEncoding) {
                        ForEach(NameEncoding.allCases) { Text($0.rawValue).tag($0) }
                    }
                    Toggle("Zip64 항상 사용", isOn: $zip64)
                }

                Section {
                    Button("zip 만들기") { create() }
                        .disabled(files.isEmpty || (encryption != .none && password.isEmpty))
                    if let created {
                        ShareLink(item: created) { Label(created.lastPathComponent, systemImage: "square.and.arrow.up") }
                    }
                    if let summary { Text(summary).font(.footnote) }
                    if let errorMessage { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle("만들기")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: true) { picked in
                if case .success(let urls) = picked {
                    files = urls.compactMap { try? copyToTemporary($0) }
                }
            }
        }
    }

    private func create() {
        errorMessage = nil
        summary = nil
        var options = WriteOptions()
        options.compression = compression ? .deflate : .store
        options.encryption = encryption.method
        options.password = encryption == .none ? nil : Password(password)
        options.filenameEncoding = nameEncoding == .cp949 ? .cp949 : .utf8
        options.zip64 = zip64 ? .always : .automatic

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Satchel-\(timestamp()).zip")
        do {
            let result = try Zip.create(at: url, from: files, options: options)
            created = url
            let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? 0
            summary = "항목 \(result.entries.count)개 · \(ByteCountFormatter.string(fromByteCount: size, countStyle: .file))"
                + (result.usedZip64 ? " · Zip64" : "")
        } catch {
            errorMessage = describe(error)
        }
    }
}
