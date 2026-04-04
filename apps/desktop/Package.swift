// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Ilvarion",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .executable(name: "Ilvarion", targets: ["Ilvarion"]),
        .executable(name: "ilvarion-mcp-wrapper", targets: ["MCPWrapper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "Ilvarion",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
            ],
            resources: [
                .copy("Resources"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .executableTarget(
            name: "MCPWrapper",
            dependencies: [],
            path: "Sources/MCPWrapper",
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ]
        ),
        .testTarget(
            name: "IlvarionTests",
            dependencies: ["Ilvarion"]
        ),
    ]
)
