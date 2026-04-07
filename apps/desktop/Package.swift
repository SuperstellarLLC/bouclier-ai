// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Bouclier",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .executable(name: "Bouclier", targets: ["Bouclier"]),
        .executable(name: "bouclier-ai-mcp-wrapper", targets: ["MCPWrapper"]),
        .executable(name: "bouclier-ai-env", targets: ["EnvHelper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.76.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.29.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.23.0"),
        .package(url: "https://github.com/sparkle-project/Sparkle.git", from: "2.6.0"),
    ],
    targets: [
        .executableTarget(
            name: "Bouclier",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "Sparkle", package: "Sparkle"),
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
        .executableTarget(
            name: "BouclierExtension",
            dependencies: [],
            path: "Sources/BouclierExtension",
            exclude: ["GeneratedInfo.plist"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .unsafeFlags(["-Xfrontend", "-enable-upcoming-feature", "-Xfrontend", "InternalImportsByDefault"], .when(platforms: [])),
            ],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
            ]
        ),
        .testTarget(
            name: "BouclierTests",
            dependencies: [
                "Bouclier",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ]
        ),
    ]
)
