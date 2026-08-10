import Foundation
import Testing
@testable import Bouclier

/// **What we can and can't test here.**
///
/// PIIClassifier's full inference path requires the bundled
/// `Piiranha.mlpackage` + `PiiranhaTokenizer/` + `piiranha-labels.json`
/// to be present in `Resources/`. Those artefacts are produced by
/// `apps/desktop/scripts/convert-piiranha.py` and intentionally NOT
/// checked into git (the .mlpackage is ~280 MB).
///
/// CI and local dev runs therefore have to exercise the **graceful
/// degradation** path: the classifier throws a documented error when
/// any artefact is missing, and the rest of the proxy continues on the
/// regex + native tiers without it.
///
/// End-to-end inference correctness is exercised by the user's own
/// `swift test` run on a machine where the conversion script has been
/// executed, plus by the `bench-piiranha.py` harness on the same
/// artefacts before each release.
@Suite("PIIClassifier — graceful degradation when model is unbundled")
struct PIIClassifierTests {
    @Test("init() either loads cleanly or throws a documented error")
    func initContract() async {
        // Two valid outcomes here. Both are tested as a single
        // expectation because the bundle state varies between
        // environments:
        //
        // 1. On CI / fresh checkouts, `Piiranha.mlpackage` is
        //    gitignored (~280 MB), so init throws `.modelNotFound`
        //    or one of the other documented errors.
        // 2. On a contributor's machine after they've run
        //    `scripts/convert-piiranha.py`, all three artefacts are
        //    present and init returns a working classifier.
        //
        // Either way the contract holds: the proxy never crashes;
        // failures surface through `ClassifierError.description`.
        do {
            _ = try await PIIClassifier()
            // Loaded successfully — that's a valid outcome.
        } catch let err as PIIClassifier.ClassifierError {
            #expect(!err.description.isEmpty)
        } catch {
            Issue.record("Unexpected error type \(type(of: error)): \(error)")
        }
    }

    @Test("Errors describe themselves so the menu-bar badge can render the reason")
    func errorsAreLoggable() {
        // Spot-check that each error case has a non-empty description —
        // PatternManager renders these strings inline.
        let cases: [PIIClassifier.ClassifierError] = [
            .modelNotFound,
            .tokenizerNotFound,
            .labelMapNotFound,
            .labelMapInvalid("missing key"),
            .predictionFailed("CoreML quark"),
            .invalidOutput,
        ]
        for err in cases {
            #expect(!err.description.isEmpty)
        }
    }

    @Test("PIIScanner.hasMLClassifier reflects whether one is attached")
    func scannerExposesMLState() {
        let plain = PIIScanner()
        #expect(!plain.hasMLClassifier)
    }
}
