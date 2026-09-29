import SwiftUI

@main
struct SatchelExampleApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                ExtractView()
                    .tabItem { Label("열기", systemImage: "archivebox") }
                CreateView()
                    .tabItem { Label("만들기", systemImage: "plus.rectangle.on.folder") }
            }
        }
    }
}
