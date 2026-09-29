// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Satchel",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "Satchel", targets: ["Satchel"]),
    ],
    targets: [
        .target(name: "Satchel"),
        .testTarget(name: "SatchelTests", dependencies: ["Satchel"]),
    ]
)
