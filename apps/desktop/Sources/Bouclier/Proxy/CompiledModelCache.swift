import CoreML
import CryptoKit
import Foundation

/// Compiles raw CoreML packages on demand without letting a previous model
/// release survive forever under a fixed cache filename.
///
/// Release builds normally bundle `.mlmodelc` and never enter this path. The
/// raw-package fallback keys its Application Support cache by app version,
/// operating-system version, package metadata, complete hashes of small model
/// files, and bounded samples of large weight files. A release version change
/// therefore always invalidates the cache without hashing hundreds of MB at
/// launch. For the unsigned raw development fallback, metadata plus sampling
/// catches ordinary replacements but is intentionally not a full-file
/// integrity guarantee; signed artifacts receive full hash verification before
/// packaging.
enum CompiledModelCache {
    enum CacheError: Error {
        case invalidPackage(URL)
    }

    private static let fingerprintSchema = "compiled-model-cache-v1"
    private static let fullHashThreshold = 1 * 1024 * 1024
    private static let sampleSize = 64 * 1024

    static func compiledCopy(of rawPackage: URL, modelName: String) throws -> URL {
        let supportDir = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("ai.bouclier.app/compiled-models", isDirectory: true)
        try FileManager.default.createDirectory(
            at: supportDir,
            withIntermediateDirectories: true
        )

        let cacheName = try cacheDirectoryName(
            for: rawPackage,
            modelName: modelName,
            applicationVersion: applicationVersionIdentity,
            operatingSystemVersion: operatingSystemIdentity
        )
        let cachedURL = supportDir.appendingPathComponent(cacheName, isDirectory: true)
        if FileManager.default.fileExists(atPath: cachedURL.path) {
            removeObsoleteCopies(
                modelName: modelName,
                keeping: cachedURL,
                in: supportDir
            )
            return cachedURL
        }

        let freshCompiled = try MLModel.compileModel(at: rawPackage)
        do {
            try FileManager.default.moveItem(at: freshCompiled, to: cachedURL)
        } catch {
            // A concurrent initializer or process may have won the same
            // deterministic destination after our initial existence check.
            if FileManager.default.fileExists(atPath: cachedURL.path) {
                try? FileManager.default.removeItem(at: freshCompiled)
            } else {
                throw error
            }
        }
        removeObsoleteCopies(modelName: modelName, keeping: cachedURL, in: supportDir)
        return cachedURL
    }

    /// Internal for focused tests; callers use `compiledCopy`.
    static func cacheDirectoryName(
        for rawPackage: URL,
        modelName: String,
        applicationVersion: String,
        operatingSystemVersion: String
    ) throws -> String {
        var hasher = SHA256()
        update(&hasher, with: fingerprintSchema)
        update(&hasher, with: modelName)
        update(&hasher, with: applicationVersion)
        update(&hasher, with: operatingSystemVersion)
        try update(&hasher, withPackageAt: rawPackage)
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return "\(modelName)-\(digest).mlmodelc"
    }

    private static var applicationVersionIdentity: String {
        let shortVersion = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String ?? "unversioned"
        let buildVersion = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String ?? "unversioned"
        return "\(shortVersion)+\(buildVersion)"
    }

    private static var operatingSystemIdentity: String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    private static func update(_ hasher: inout SHA256, with value: String) {
        hasher.update(data: Data(value.utf8))
        hasher.update(data: Data([0]))
    }

    private static func update(_ hasher: inout SHA256, withPackageAt rawPackage: URL) throws {
        let rootValues = try rawPackage.resourceValues(
            forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        )
        guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else {
            throw CacheError.invalidPackage(rawPackage)
        }

        let keys: Set<URLResourceKey> = [
            .contentModificationDateKey,
            .fileSizeKey,
            .isRegularFileKey,
            .isSymbolicLinkKey,
        ]
        guard let enumerator = FileManager.default.enumerator(
            at: rawPackage,
            includingPropertiesForKeys: Array(keys),
            options: [.skipsHiddenFiles]
        ) else {
            throw CacheError.invalidPackage(rawPackage)
        }

        var files: [URL] = []
        for case let candidate as URL in enumerator {
            let values = try candidate.resourceValues(forKeys: keys)
            if values.isSymbolicLink == true {
                throw CacheError.invalidPackage(rawPackage)
            }
            if values.isRegularFile == true {
                files.append(candidate)
            }
        }
        guard !files.isEmpty else { throw CacheError.invalidPackage(rawPackage) }

        let rootPath = rawPackage.standardizedFileURL.path + "/"
        for file in files.sorted(by: { $0.path < $1.path }) {
            let values = try file.resourceValues(forKeys: keys)
            let path = file.standardizedFileURL.path
            guard path.hasPrefix(rootPath), let fileSize = values.fileSize else {
                throw CacheError.invalidPackage(rawPackage)
            }
            let relativePath = String(path.dropFirst(rootPath.count))
            update(&hasher, with: relativePath)
            update(&hasher, with: String(fileSize))
            update(
                &hasher,
                with: String(values.contentModificationDate?.timeIntervalSince1970.bitPattern ?? 0)
            )
            try update(&hasher, withFileContentsAt: file, size: fileSize)
        }
    }

    private static func update(
        _ hasher: inout SHA256,
        withFileContentsAt file: URL,
        size: Int
    ) throws {
        if size <= fullHashThreshold {
            hasher.update(data: try Data(contentsOf: file, options: .mappedIfSafe))
            return
        }

        let maximumOffset = max(0, size - sampleSize)
        let offsets = Set([
            0,
            maximumOffset / 4,
            maximumOffset / 2,
            maximumOffset * 3 / 4,
            maximumOffset,
        ]).sorted()
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        for offset in offsets {
            update(&hasher, with: "sample:\(offset)")
            try handle.seek(toOffset: UInt64(offset))
            if let data = try handle.read(upToCount: sampleSize) {
                hasher.update(data: data)
            }
        }
    }

    private static func removeObsoleteCopies(
        modelName: String,
        keeping current: URL,
        in supportDir: URL
    ) {
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: supportDir,
            includingPropertiesForKeys: nil
        ) else { return }

        let legacyName = "\(modelName).mlmodelc"
        let versionedPrefix = "\(modelName)-"
        for entry in entries where entry != current {
            let name = entry.lastPathComponent
            let isModelCache = name == legacyName
                || (name.hasPrefix(versionedPrefix) && name.hasSuffix(".mlmodelc"))
            if isModelCache {
                try? FileManager.default.removeItem(at: entry)
            }
        }
    }
}
