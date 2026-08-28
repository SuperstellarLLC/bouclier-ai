import Foundation

/// Resolves resources in both SwiftPM development builds and the manually
/// assembled release app.
///
/// SwiftPM's generated `Bundle.module` accessor looks for
/// `Bouclier_Bouclier.bundle` beside `Bundle.main.bundleURL` and then falls
/// back to an absolute `.build` path from the compile machine. Our signed app
/// correctly embeds that resource bundle under `Contents/Resources`, so using
/// the generated accessor directly can fatal-error after the app is moved to a
/// different Mac. Prefer the embedded bundle explicitly and evaluate
/// `Bundle.module` only for `swift run` / `swift test`.
enum BouclierResources {
    static let bundle: Bundle = {
        let bundleName = "Bouclier_Bouclier.bundle"
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent(bundleName),
            // Keep compatibility with SwiftPM's generated layout if a future
            // packaging path places the resource bundle beside the main one.
            Bundle.main.bundleURL.appendingPathComponent(bundleName),
        ].compactMap { $0 }

        for candidate in candidates {
            if let embedded = Bundle(url: candidate) {
                return embedded
            }
        }

        #if SWIFT_PACKAGE
        return Bundle.module
        #else
        return Bundle.main
        #endif
    }()

    static func url(
        forResource name: String,
        withExtension extensionName: String?
    ) -> URL? {
        // Xcode may flatten target resources into the main app bundle; prefer
        // that valid layout before consulting the nested SwiftPM bundle.
        Bundle.main.url(forResource: name, withExtension: extensionName)
            ?? bundle.url(forResource: name, withExtension: extensionName)
    }
}
