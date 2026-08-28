import Foundation
import Testing
@testable import Bouclier

@Suite("Compiled model cache invalidation")
struct CompiledModelCacheTests {
    @Test("Cache key is stable while package and release identity are unchanged")
    func stableKey() throws {
        let package = try makePackage()
        defer { try? FileManager.default.removeItem(at: package.deletingLastPathComponent()) }

        let first = try cacheName(for: package)
        let second = try cacheName(for: package)

        #expect(first == second)
        #expect(first.hasPrefix("PromptGuard2-"))
        #expect(first.hasSuffix(".mlmodelc"))
    }

    @Test("App or OS release change invalidates the compiled cache")
    func releaseIdentityInvalidates() throws {
        let package = try makePackage()
        defer { try? FileManager.default.removeItem(at: package.deletingLastPathComponent()) }

        let baseline = try cacheName(for: package)
        let newApp = try cacheName(for: package, appVersion: "2.0+2")
        let newOS = try cacheName(for: package, osVersion: "16.0.0")

        #expect(baseline != newApp)
        #expect(baseline != newOS)
    }

    @Test("Small package metadata changes invalidate even with preserved timestamp")
    func manifestContentsInvalidate() throws {
        let package = try makePackage()
        defer { try? FileManager.default.removeItem(at: package.deletingLastPathComponent()) }
        let manifest = package.appendingPathComponent("Manifest.json")
        let originalDate = try manifest.resourceValues(
            forKeys: [.contentModificationDateKey]
        ).contentModificationDate
        let baseline = try cacheName(for: package)

        try Data("{\"version\":2}".utf8).write(to: manifest)
        if let originalDate {
            try FileManager.default.setAttributes(
                [.modificationDate: originalDate],
                ofItemAtPath: manifest.path
            )
        }

        #expect(try cacheName(for: package) != baseline)
    }

    @Test("A sampled large-weight change invalidates without reading the whole file")
    func sampledWeightContentsInvalidate() throws {
        let package = try makePackage(largeWeight: true)
        defer { try? FileManager.default.removeItem(at: package.deletingLastPathComponent()) }
        let weight = package.appendingPathComponent("Data/weights/weight.bin")
        let originalDate = try weight.resourceValues(
            forKeys: [.contentModificationDateKey]
        ).contentModificationDate
        let baseline = try cacheName(for: package)

        let handle = try FileHandle(forWritingTo: weight)
        try handle.seek(toOffset: 1)
        try handle.write(contentsOf: Data([0x7f]))
        try handle.close()
        if let originalDate {
            try FileManager.default.setAttributes(
                [.modificationDate: originalDate],
                ofItemAtPath: weight.path
            )
        }

        #expect(try cacheName(for: package) != baseline)
    }

    private func cacheName(
        for package: URL,
        appVersion: String = "1.0+1",
        osVersion: String = "15.0.0"
    ) throws -> String {
        try CompiledModelCache.cacheDirectoryName(
            for: package,
            modelName: "PromptGuard2",
            applicationVersion: appVersion,
            operatingSystemVersion: osVersion
        )
    }

    private func makePackage(largeWeight: Bool = false) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let package = root.appendingPathComponent("Model.mlpackage", isDirectory: true)
        let weights = package.appendingPathComponent("Data/weights", isDirectory: true)
        try FileManager.default.createDirectory(at: weights, withIntermediateDirectories: true)
        try Data("{\"version\":1}".utf8).write(
            to: package.appendingPathComponent("Manifest.json")
        )
        let byteCount = largeWeight ? 2 * 1024 * 1024 : 128
        try Data(repeating: 0x2a, count: byteCount).write(
            to: weights.appendingPathComponent("weight.bin")
        )
        return package
    }
}
