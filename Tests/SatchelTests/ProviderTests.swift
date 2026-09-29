import Foundation
import XCTest
@testable import Satchel

/// 비밀번호 제공자 흐름 — 재시도 · 기억 · 건너뛰기 · 취소.
final class ProviderTests: XCTestCase {

    actor Log {
        var requests: [(String, Int, PasswordRequest.Reason)] = []
        func add(_ r: PasswordRequest) { requests.append((r.entry.path, r.attempt, r.reason)) }
    }

    private func archive(_ entries: [(String, String?)], in dir: TempDir) throws -> URL {
        let writer = ArchiveWriter()
        for (name, password) in entries {
            let options = password.map { EntryOptions(encryption: .aes(), password: Password($0)) }
            try writer.add(Data("content of \(name)".utf8), as: name, options: options)
        }
        let url = dir.path("p.zip")
        try writer.finishData().write(to: url)
        return url
    }

    func testRetryUntilCorrect() async throws {
        let dir = try TempDir()
        let zip = try archive([("a.txt", "right")], in: dir)
        let log = Log()
        let provider = ClosurePasswordProvider { request in
            await log.add(request)
            return .password(Password(request.attempt < 3 ? "wrong\(request.attempt)" : "right"))
        }
        let result = try await Zip.extract(zip, to: dir.path("out"), passwordProvider: provider)
        XCTAssertEqual(result.extracted.map(\.path), ["a.txt"])
        let requests = await log.requests
        XCTAssertEqual(requests.map(\.1), [1, 2, 3])
        XCTAssertEqual(requests.map(\.2), [.required, .wrongPassword, .wrongPassword])
    }

    func testKnownPasswordIsReused() async throws {
        let dir = try TempDir()
        let zip = try archive([("a.txt", "same"), ("plain.txt", nil), ("b.txt", "same"), ("c.txt", "other")], in: dir)
        let log = Log()
        let provider = ClosurePasswordProvider { request in
            await log.add(request)
            return .password(Password(request.entry.path == "c.txt" ? "other" : "same"))
        }
        try await Zip.extract(zip, to: dir.path("out"), passwordProvider: provider)
        let asked = await log.requests.map(\.0)
        XCTAssertEqual(asked, ["a.txt", "c.txt"])   // b.txt 는 기억한 비밀번호로 풀린다
        XCTAssertEqual(try String(contentsOf: dir.path("out/b.txt"), encoding: .utf8), "content of b.txt")
    }

    func testOptionsPasswordTriedFirst() async throws {
        let dir = try TempDir()
        let zip = try archive([("a.txt", "preset")], in: dir)
        var options = ExtractOptions()
        options.password = Password("preset")
        let provider = ClosurePasswordProvider { _ in
            XCTFail("should not ask")
            return .cancel
        }
        try await Zip.extract(zip, to: dir.path("out"), options: options, passwordProvider: provider)
    }

    func testPasswordsCandidates() async throws {
        let dir = try TempDir()
        let zip = try archive([("a.txt", "third")], in: dir)
        let provider = ClosurePasswordProvider { _ in .passwords([Password("first"), Password("second"), Password("third")]) }
        let result = try await Zip.extract(zip, to: dir.path("out"), passwordProvider: provider)
        XCTAssertEqual(result.extracted.count, 1)
    }

    func testSkipEntry() async throws {
        let dir = try TempDir()
        let zip = try archive([("keep.txt", nil), ("locked.txt", "x")], in: dir)
        let provider = ClosurePasswordProvider { _ in .skipEntry }
        let result = try await Zip.extract(zip, to: dir.path("out"), passwordProvider: provider)
        XCTAssertEqual(result.extracted.map(\.path), ["keep.txt"])
        XCTAssertEqual(result.skipped.map(\.path), ["locked.txt"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("out/locked.txt").path))
    }

    func testCancelLeavesNothing() async throws {
        let dir = try TempDir()
        let zip = try archive([("plain.txt", nil), ("locked.txt", "x")], in: dir)
        let provider = ClosurePasswordProvider { _ in .cancel }
        do {
            try await Zip.extract(zip, to: dir.path("out"), passwordProvider: provider)
            XCTFail("expected cancel")
        } catch let e as ZipError {
            XCTAssertEqual(e, .cancelled)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("out").path))
        XCTAssertEqual(try dir.leftovers(), [])
    }

    func testTaskCancellation() async throws {
        let dir = try TempDir()
        let zip = try archive([("locked.txt", "x")], in: dir)
        let out = dir.path("out")
        let task = Task {
            try await Zip.extract(zip, to: out, passwordProvider: ClosurePasswordProvider { _ in
                withUnsafeCurrentTask { $0?.cancel() }
                return .password(Password("x"))
            })
        }
        do {
            _ = try await task.value
            XCTFail("expected cancel")
        } catch let e as ZipError {
            XCTAssertEqual(e, .cancelled)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("out").path))
    }
}
