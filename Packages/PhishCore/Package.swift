// swift-tools-version: 6.0
// PhishCore: pure Swift, cross-platform (iOS + macOS), no UIKit. `swift test`-able on macOS.
import PackageDescription

let package = Package(
    name: "PhishCore",
    platforms: [
        .iOS("26.0"),
        .macOS("15.0"),
    ],
    products: [
        .library(name: "PhishCore", targets: ["PhishCore"]),
    ],
    targets: [
        .target(
            name: "PhishCore",
            path: "Sources/PhishCore"
        ),
        .testTarget(
            name: "PhishCoreTests",
            dependencies: ["PhishCore"],
            path: "Tests/PhishCoreTests"
        ),
    ]
)
