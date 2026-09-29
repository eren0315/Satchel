import Satchel
import SwiftUI

/// 비밀번호 입력 창 상태. 라이브러리는 UI 를 모른다 — 샘플 앱이 `PasswordProvider` 로 창을 띄운다.
@MainActor
final class PasswordPrompt: ObservableObject {
    struct Pending: Identifiable {
        let id = UUID()
        let request: PasswordRequest
    }

    @Published var pending: Pending?
    @Published var input = ""
    private var continuation: CheckedContinuation<PasswordResponse, Never>?

    func ask(_ request: PasswordRequest) async -> PasswordResponse {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            input = ""
            pending = Pending(request: request)
        }
    }

    func answer(_ response: PasswordResponse) {
        continuation?.resume(returning: response)
        continuation = nil
        pending = nil
        input = ""
    }

    var provider: some PasswordProvider { Provider(prompt: self) }

    private struct Provider: PasswordProvider {
        let prompt: PasswordPrompt
        func password(for request: PasswordRequest) async -> PasswordResponse {
            await prompt.ask(request)
        }
    }
}

extension View {
    func passwordPrompt(_ prompt: PasswordPrompt) -> some View {
        // 응답은 버튼으로만 한다. 닫힘(false)에서 취소하면 SwiftUI 가 버튼 동작보다 먼저
        // 바인딩을 내릴 때 '확인'이 '취소'로 바뀐다.
        let isPresented = Binding(get: { prompt.pending != nil }, set: { _ in })
        return alert(title(for: prompt.pending), isPresented: isPresented, presenting: prompt.pending) { _ in
            SecureField("비밀번호", text: Binding(get: { prompt.input }, set: { prompt.input = $0 }))
            Button("확인") { prompt.answer(.password(Password(prompt.input))) }
            Button("이 파일 건너뛰기") { prompt.answer(.skipEntry) }
            Button("전체 취소", role: .cancel) { prompt.answer(.cancel) }
        } message: { pending in
            Text(pending.request.entry.path)
        }
    }

    private func title(for pending: PasswordPrompt.Pending?) -> String {
        guard let request = pending?.request else { return "" }
        switch request.reason {
        case .required: return "비밀번호가 필요합니다"
        case .wrongPassword: return "비밀번호가 틀렸습니다 (\(request.attempt)번째)"
        }
    }
}
