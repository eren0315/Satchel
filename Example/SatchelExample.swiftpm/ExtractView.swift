import Satchel
import SwiftUI
import UniformTypeIdentifiers

struct ExtractView: View {
    @StateObject private var prompt = PasswordPrompt()
    @State private var importing = false
    @State private var archiveURL: URL?
    @State private var entries: [Entry] = []
    @State private var progress: Progress?
    @State private var task: Task<Void, Never>?
    @State private var result: String?
    @State private var extractedFiles: [String] = []
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Button("zip 파일 고르기") { importing = true }
                    if let archiveURL { Text(archiveURL.lastPathComponent).font(.footnote).foregroundStyle(.secondary) }
                }

                if !entries.isEmpty {
                    Section("항목 \(entries.count)개") {
                        ForEach(entries, id: \.index) { entry in
                            EntryRow(entry: entry)
                        }
                    }
                    Section {
                        if let progress {
                            ProgressView(progress)
                            Button("취소", role: .destructive) { progress.cancel(); task?.cancel() }
                        } else {
                            Button("전부 풀기") { extract() }
                        }
                    }
                }

                if let result {
                    Section("결과") {
                        Text(result)
                        ForEach(extractedFiles, id: \.self) { Text($0).font(.footnote.monospaced()) }
                    }
                }
                if let errorMessage {
                    Section("오류") { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .navigationTitle("열기")
            .fileImporter(isPresented: $importing, allowedContentTypes: [.zip]) { picked in
                if case .success(let url) = picked { open(url) }
            }
            .passwordPrompt(prompt)
        }
    }

    private func open(_ picked: URL) {
        result = nil
        errorMessage = nil
        extractedFiles = []
        do {
            let local = try copyToTemporary(picked)
            archiveURL = local
            entries = try ArchiveReader(url: local).entries
        } catch {
            entries = []
            errorMessage = describe(error)
        }
    }

    private func extract() {
        guard let archiveURL else { return }
        let destination = documentsDirectory()
            .appendingPathComponent("Extracted", isDirectory: true)
            .appendingPathComponent(archiveURL.deletingPathExtension().lastPathComponent + "-" + timestamp())
        let progress = Progress()
        self.progress = progress
        errorMessage = nil
        var options = ExtractOptions()
        options.progress = progress
        let provider = prompt.provider

        task = Task {
            do {
                let r = try await Zip.extract(archiveURL, to: destination, options: options, passwordProvider: provider)
                result = "풀린 항목 \(r.extracted.count)개 · 건너뜀 \(r.skipped.count)개"
                extractedFiles = (try? FileManager.default.subpathsOfDirectory(atPath: destination.path).sorted()) ?? []
            } catch {
                errorMessage = describe(error)
            }
            self.progress = nil
            task = nil
        }
    }
}

private struct EntryRow: View {
    let entry: Entry

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(entry.path).font(.body.monospaced()).lineLimit(2)
            HStack(spacing: 6) {
                Text(ByteCountFormatter.string(fromByteCount: Int64(clamping: entry.uncompressedSize), countStyle: .file))
                if let encryption = entry.encryption {
                    Badge(text: encryption == .zipCrypto ? "ZipCrypto" : encryption == .winZipAES ? "AES" : encryption.rawValue,
                          color: encryption == .zipCrypto ? .orange : .green)
                }
                if entry.isZip64 { Badge(text: "Zip64", color: .blue) }
                if entry.kind == .directory { Badge(text: "폴더", color: .gray) }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }
}

struct Badge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}
