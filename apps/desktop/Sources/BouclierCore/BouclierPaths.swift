import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// App-support paths shared by the main app and its read-only siblings (the
/// `bouclier` CLI). The app publishes a `status.json` snapshot here; the CLI
/// reads it to answer "is Bouclier installed / running?" — counts only,
/// never request content.
public enum BouclierPaths {
    public static var appSupportDir: URL {
        // Test/CI override so the CLI can run against a throwaway directory
        // without touching the user's real store.
        let base: URL
        if let override = ProcessInfo.processInfo.environment["BOUCLIER_APP_SUPPORT_DIR"], !override.isEmpty {
            base = URL(fileURLWithPath: override, isDirectory: true)
        } else {
            base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
                .first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        }
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    /// Read-only state snapshot the app publishes for the CLI to answer
    /// "is Bouclier installed/running/healthy?" (no request content).
    public static var statusFile: URL { appSupportDir.appendingPathComponent("status.json") }
}

/// Atomic file write: temp file in the SAME directory, 0600 from birth,
/// fsync, then rename(2) — so a reader never observes a partial file and the
/// file is never briefly world-readable. (`Data.write(.atomic)` also renames,
/// but this guarantees same-dir temp + 0600-at-creation, which we want for a
/// security product.)
public enum AtomicFile {
    public static func write(_ data: Data, to dst: URL) throws {
        let dir = dst.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".tmp-\(UUID().uuidString)")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var closed = false
        func closeFd() { if !closed { close(fd); closed = true } }
        defer { closeFd() }
        try data.withUnsafeBytes { raw in
            guard var p = raw.baseAddress else { return }
            var left = raw.count
            while left > 0 {
                let n = Darwin.write(fd, p, left)
                if n < 0 {
                    let e = errno
                    unlink(tmp.path)
                    throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
                }
                p = p.advanced(by: n); left -= n
            }
        }
        fsync(fd)
        closeFd()
        if rename(tmp.path, dst.path) != 0 {
            let e = errno
            unlink(tmp.path)
            throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
        }
    }
}
