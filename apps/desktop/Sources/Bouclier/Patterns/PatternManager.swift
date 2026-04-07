import CryptoKit
import Foundation

/// Manages pattern loading with hot-reload support.
///
/// Load priority:
/// 1. User override: ~/Library/Application Support/com.bouclier.Bouclier/patterns.json
/// 2. Bundled resource: patterns.json in app bundle
/// 3. Compiled fallback: hardcoded critical patterns
///
/// Watches the user override directory for changes and swaps the active InjectionFilter.
final class PatternManager: @unchecked Sendable {
    private let lock = NSLock()
    private var _filter: InjectionFilter
    private var fileMonitor: DispatchSourceFileSystemObject?
    private var monitorFD: Int32 = -1
    private var onChange: (() -> Void)?

    static let userPatternsDir: URL = {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("com.bouclier.Bouclier", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    static let userPatternsPath: URL = userPatternsDir.appendingPathComponent("patterns.json")

    var filter: InjectionFilter {
        lock.lock()
        defer { lock.unlock() }
        return _filter
    }

    /// Initialize with optional change callback (e.g., to log reloads).
    init(onChange: (() -> Void)? = nil) {
        self.onChange = onChange

        // Load best available patterns
        if let userFilter = Self.loadFromPath(Self.userPatternsPath) {
            _filter = userFilter
        } else {
            _filter = InjectionFilter()
        }

        startWatching()
    }

    deinit {
        stopWatching()
    }

    // MARK: - Pattern Loading

    private static func loadFromPath(_ url: URL) -> InjectionFilter? {
        guard FileManager.default.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url),
              let patternSet = try? JSONDecoder().decode(PatternSetJSON.self, from: data)
        else { return nil }

        let compiled = patternSet.patterns.compactMap { FilterPattern(from: $0) }
        guard !compiled.isEmpty else { return nil }

        let hash = SHA256.hash(data: data)
        let hashPrefix = hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[bouclier.ai] Loaded \(compiled.count) patterns from \(url.lastPathComponent) (SHA-256: \(hashPrefix)...)")

        return InjectionFilter(patterns: compiled)
    }

    // MARK: - File Watching

    private func startWatching() {
        let dirPath = Self.userPatternsDir.path

        monitorFD = open(dirPath, O_EVTONLY)
        guard monitorFD >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: monitorFD,
            eventMask: [.write, .rename],
            queue: .global(qos: .utility)
        )

        source.setEventHandler { [weak self] in
            self?.handleChange()
        }

        source.setCancelHandler { [weak self] in
            guard let self, monitorFD >= 0 else { return }
            close(monitorFD)
            monitorFD = -1
        }

        source.resume()
        fileMonitor = source
    }

    private func stopWatching() {
        fileMonitor?.cancel()
        fileMonitor = nil
    }

    private func handleChange() {
        // Brief delay for file writes to settle
        Thread.sleep(forTimeInterval: 0.3)

        if let newFilter = Self.loadFromPath(Self.userPatternsPath) {
            lock.lock()
            _filter = newFilter
            lock.unlock()
            print("[bouclier.ai] Patterns hot-reloaded")
            onChange?()
        }
    }
}
