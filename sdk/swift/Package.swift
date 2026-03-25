// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenTrustRegistry",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "OpenAgentTrustRegistry",
            targets: ["OpenAgentTrustRegistry"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0")
    ],
    targets: [
        .target(
            name: "OpenAgentTrustRegistry",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ],
            resources: [
                .process("Resources")
            ]
        ),
        .testTarget(
            name: "OpenAgentTrustRegistryTests",
            dependencies: ["OpenAgentTrustRegistry"]
        ),
    ]
)
