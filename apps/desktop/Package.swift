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
        .executable(name: "ilvarion-env", targets: ["EnvHelper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.76.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.29.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.23.0"),
    ],
    targets: [
        .executableTarget(
            name: "Ilvarion",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
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
        .executableTarget(
            name: "EnvHelper",
            dependencies: [],
            path: "Sources/EnvHelper",
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
