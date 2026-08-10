import Foundation
import Testing
@testable import Bouclier

/// The "what's new" sheet has bitten users twice now: once because it
/// never showed (markSeen ran too early), once because it showed every
/// launch (markSeen was wired to a dismiss callback that the window's
/// red-X traffic-light button bypassed). These tests pin the contract:
/// `shouldShow` is true once per version watermark, `markSeen` advances
/// the watermark, and nothing else mutates it.
@Suite("ReleaseNotes — version watermark", .serialized)
struct ReleaseNotesTests {
    private static let key = "releaseNotesSeenVersion"

    private static func clearWatermark() {
        UserDefaults.standard.removeObject(forKey: key)
    }

    private static func setWatermark(_ value: String) {
        UserDefaults.standard.set(value, forKey: key)
    }

    @Test("First launch on a fresh install — should show")
    func firstLaunchShows() {
        Self.clearWatermark()
        defer { Self.clearWatermark() }
        #expect(ReleaseNotes.shouldShow())
    }

    @Test("After markSeen on the current version, do not show again")
    func markSeenSuppresses() {
        Self.clearWatermark()
        defer { Self.clearWatermark() }
        ReleaseNotes.markSeen()
        #expect(!ReleaseNotes.shouldShow(),
                "Second launch on the same version must not re-trigger the sheet")
    }

    @Test("Watermark from a prior version still triggers the sheet")
    func oldWatermarkStillShows() {
        Self.setWatermark("0.0.1-ancient")
        defer { Self.clearWatermark() }
        #expect(ReleaseNotes.shouldShow(),
                "Bumping the bundle version is the whole reason we keep a watermark")
    }

    @Test("Calling markSeen twice does not re-arm the sheet")
    func doubleMarkSeenIsIdempotent() {
        Self.clearWatermark()
        defer { Self.clearWatermark() }
        ReleaseNotes.markSeen()
        ReleaseNotes.markSeen()
        #expect(!ReleaseNotes.shouldShow())
    }
}
