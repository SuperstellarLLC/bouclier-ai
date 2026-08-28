import Foundation
import Testing

@Suite("Desktop build metadata")
struct BuildMetadataTests {
    @Test("Packaged app requires the same macOS version as SwiftPM and Info.plist")
    func packagedAppMinimumSystemVersion() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let packageRoot = testFile
            .deletingLastPathComponent() // BouclierTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // apps/desktop
        let scriptURL = packageRoot.appendingPathComponent("scripts/build-app.sh")
        let script = try String(contentsOf: scriptURL, encoding: .utf8)
        let package = try String(
            contentsOf: packageRoot.appendingPathComponent("Package.swift"),
            encoding: .utf8
        )
        let sourcePlist = try String(
            contentsOf: packageRoot.appendingPathComponent("Sources/Bouclier/Resources/Info.plist"),
            encoding: .utf8
        )

        #expect(script.contains("<key>LSMinimumSystemVersion</key><string>15.0</string>"))
        #expect(!script.contains("<key>LSMinimumSystemVersion</key><string>14.0</string>"))
        #expect(package.contains(".macOS(.v15)"))
        #expect(sourcePlist.contains("<key>LSMinimumSystemVersion</key>\n    <string>15.0</string>"))
    }
}
