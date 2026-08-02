import CryptoKit
import Foundation

/// Manages pattern loading with hot-reload support.
///
/// Load priority:
/// 1. User override: ~/Library/Application Support/ai.bouclier.app/patterns.json
/// 2. Bundled resource: patterns.json in app bundle
/// 3. Compiled fallback: hardcoded critical patterns
///
/// Watches the user override directory for changes and swaps the active InjectionFilter.
///
/// On startup also kicks off an async load of the bundled CoreML
/// classifier (Meta Prompt Guard 2). The classifier takes ~200-500ms
/// to compile + load on first launch, so the filter starts in
/// regex-only mode and swaps to a fused (regex+ML+entropy) filter the
/// moment the classifier is ready. If the model fails to load (missing
/// `.mlpackage`, unsupported hardware, etc.) the filter stays in
/// regex-only mode for the lifetime of the process.
final class PatternManager: @unchecked Sendable {
    private let lock = NSLock()
    private var _filter: InjectionFilter
    private var _patterns: [FilterPattern]
    private var _classifier: MLClassifier?
    private var _classifierLoadError: String?
    private var _piiClassifier: PIIClassifier?
    private var _piiClassifierLoadError: String?
    private var fileMonitor: DispatchSourceFileSystemObject?
    private var monitorFD: Int32 = -1
    private var onChange: (() -> Void)?

    /// Reason the injection classifier (Prompt Guard 2) failed to load.
    var classifierLoadError: String? {
        lock.lock()
        defer { lock.unlock() }
        return _classifierLoadError
    }

    /// Reason the PII classifier (Piiranha) failed to load. Nil while
    /// loading or on success. Distinct from `classifierLoadError` —
    /// users can have one tier active without the other.
    var piiClassifierLoadError: String? {
        lock.lock()
        defer { lock.unlock() }
        return _piiClassifierLoadError
    }

    /// Whether the PII ML tier (Piiranha) is currently active.
    var hasPIIClassifier: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _piiClassifier != nil
    }

    static let userPatternsDir: URL = {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
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
    ///
    /// - Parameter loadPIITier: whether to also kick off the Piiranha PII
    ///   classifier load. The PII path has had no caller since v0.7.0 and
    ///   its model is no longer bundled, so the gateway passes `false` and
    ///   skips a background task that can only fail. Defaults to `true`
    ///   so the existing tests keep exercising both loaders.
    init(onChange: (() -> Void)? = nil, loadPIITier: Bool = true) {
        self.onChange = onChange

        // Load best available patterns
        if let userPatterns = Self.loadPatternsFromPath(Self.userPatternsPath) {
            _patterns = userPatterns
        } else {
            _patterns = Self.bundledOrFallbackPatterns()
        }
        _classifier = nil
        _filter = InjectionFilter(patterns: _patterns, classifier: nil)
        // Publish immediately in regex-only mode so the gateway is
        // protected from the first request, not from whenever CoreML
        // finishes loading (which, with the models unbundled since
        // v0.7.0, may be never).
        InjectionFilter.active.install(_filter)

        startWatching()
        Task.detached(priority: .utility) { [weak self] in
            await self?.loadClassifierAsync()
        }
        if loadPIITier {
            Task.detached(priority: .utility) { [weak self] in
                await self?.loadPIIClassifierAsync()
            }
        }
    }

    /// Load the PII NER classifier (Piiranha mDeBERTa-v3) on a
    /// background task and swap the process-wide active PII scanner
    /// when ready. Failure is non-fatal — the redactor stays on
    /// regex+native for the rest of the process. Mirrors
    /// `loadClassifierAsync()` line-for-line.
    private func loadPIIClassifierAsync() async {
        do {
            let classifier = try await PIIClassifier()
            installPIIClassifier(classifier)
        } catch {
            recordPIIClassifierLoadFailure(error)
        }
    }

    private func recordPIIClassifierLoadFailure(_ error: Error) {
        let reason = "\(error)"
        lock.lock()
        _piiClassifierLoadError = reason
        lock.unlock()
        print("[bouclier.ai] PII ML classifier unavailable, staying on regex+native: \(reason)")
        onChange?()
    }

    private func installPIIClassifier(_ classifier: PIIClassifier) {
        lock.lock()
        _piiClassifier = classifier
        let scanner = PIIScanner(mlClassifier: classifier)
        lock.unlock()
        // Swap the process-wide active scanner so new and existing
        // multimodal scans pick up the ML tier on their next attachment.
        PIIScanner.active.install(scanner)
        print("[bouclier.ai] PII ML classifier loaded — fused PII detection active (regex + native + Piiranha)")
        onChange?()
    }

    /// Load the on-device CoreML classifier on a background task and
    /// swap the active filter when ready. Failure is non-fatal — the
    /// filter stays in regex-only mode for the rest of the process.
    /// Both outcomes fire onChange so the UI can transition out of the
    /// "loading" state either way.
    private func loadClassifierAsync() async {
        do {
            let classifier = try await MLClassifier()
            installClassifier(classifier)
        } catch {
            recordClassifierLoadFailure(error)
        }
    }

    private func recordClassifierLoadFailure(_ error: Error) {
        let reason = "\(error)"
        lock.lock()
        _classifierLoadError = reason
        lock.unlock()
        print("[bouclier.ai] ML classifier unavailable, staying in regex-only mode: \(reason)")
        onChange?()
    }

    /// Synchronous critical section for swapping the active filter to
    /// one that includes the ML classifier. Split out from the async
    /// loader because Swift 6 disallows `NSLock` mutation from async
    /// contexts.
    private func installClassifier(_ classifier: MLClassifier) {
        lock.lock()
        _classifier = classifier
        _filter = InjectionFilter(patterns: _patterns, classifier: classifier)
        InjectionFilter.active.install(_filter)
        let count = _patterns.count
        lock.unlock()
        print("[bouclier.ai] ML classifier loaded — fused detection active (\(count) patterns + Prompt Guard 2)")
        onChange?()
    }

    deinit {
        stopWatching()
    }

    // MARK: - Pattern Loading

    /// Load and compile patterns from a JSON file. Returns the compiled
    /// pattern array (not a fully-built filter) so the caller can pair
    /// them with the latest classifier when constructing a filter.
    private static func loadPatternsFromPath(_ url: URL) -> [FilterPattern]? {
        guard FileManager.default.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url),
              let patternSet = try? JSONDecoder().decode(PatternSetJSON.self, from: data)
        else { return nil }

        let compiled = patternSet.patterns.compactMap { FilterPattern(from: $0) }
        guard !compiled.isEmpty else { return nil }

        let hash = SHA256.hash(data: data)
        let hashPrefix = hash.prefix(8).map { String(format: "%02x", $0) }.joined()
        print("[bouclier.ai] Loaded \(compiled.count) patterns from \(url.lastPathComponent) (SHA-256: \(hashPrefix)...)")
        return compiled
    }

    /// Pull the bundled patterns out of a default-constructed filter so
    /// PatternManager can rebuild filters with new classifiers without
    /// going back to disk. Slightly indirect because `InjectionFilter`
    /// owns its own loader, but keeps a single source of truth for the
    /// bundled-pattern fallback path.
    private static func bundledOrFallbackPatterns() -> [FilterPattern] {
        let temp = InjectionFilter()
        return temp.allPatterns
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

        guard let newPatterns = Self.loadPatternsFromPath(Self.userPatternsPath) else {
            return
        }
        lock.lock()
        _patterns = newPatterns
        // Preserve any classifier that has already been loaded so we
        // don't lose ML detection on every patterns.json edit.
        _filter = InjectionFilter(patterns: newPatterns, classifier: _classifier)
        InjectionFilter.active.install(_filter)
        lock.unlock()
        print("[bouclier.ai] Patterns hot-reloaded")
        onChange?()
    }
}
