// swift-tools-version: 5.9

// Xcode 로 이 폴더(SatchelExample.swiftpm)를 열면 iOS 앱으로 실행된다.
// 실기기에서 돌리려면 Xcode 의 Signing & Capabilities 에서 자신의 팀을 고른다.

import AppleProductTypes
import PackageDescription

let package = Package(
    name: "SatchelExample",
    platforms: [
        // 라이브러리는 iOS 15+. 샘플만 16 — NavigationStack · ShareLink (Example/README.md)
        .iOS("16.0"),
    ],
    products: [
        .iOSApplication(
            name: "SatchelExample",
            targets: ["AppModule"],
            bundleIdentifier: "io.github.eren0315.SatchelExample",
            displayVersion: "0.1.0",
            bundleVersion: "1",
            appIcon: .placeholder(icon: .box),
            accentColor: .presetColor(.brown),
            supportedDeviceFamilies: [.pad, .phone],
            supportedInterfaceOrientations: [.portrait, .landscapeLeft, .landscapeRight]
        ),
    ],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "AppModule",
            dependencies: [.product(name: "Satchel", package: "Satchel")],
            path: "."
        ),
    ]
)
