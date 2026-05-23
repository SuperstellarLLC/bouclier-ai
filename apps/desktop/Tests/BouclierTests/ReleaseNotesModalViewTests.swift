import SwiftUI
import Testing
import ViewInspector
@testable import Bouclier

/// View-level tests for `ReleaseNotesModal`. The earlier session shipped
/// a fix where dismissing via the window's red-X bypassed `onDismiss`
/// and re-armed the modal on every launch. `ReleaseNotesTests` pins the
/// watermark contract; this suite pins the *view* contract: that the
/// modal exposes the three actions a user can take (Read terms, Later,
/// Open Privacy settings) and that each one invokes the matching
/// callback. Without it, a refactor could silently drop the "Open
/// Privacy" button and CI would still be green.
@Suite("ReleaseNotesModal — view structure")
@MainActor
struct ReleaseNotesModalViewTests {
    @Test("Later button invokes onDismiss")
    func laterButtonDismisses() throws {
        var dismissed = false
        let view = ReleaseNotesModal(
            version: "1.2.3",
            onOpenPrivacySettings: {},
            onDismiss: { dismissed = true }
        )
        try view.inspect().find(button: "Later").tap()
        #expect(dismissed)
    }

    @Test("Open Privacy settings invokes both callbacks")
    func openPrivacyInvokesBoth() throws {
        var opened = false
        var dismissed = false
        let view = ReleaseNotesModal(
            version: "1.2.3",
            onOpenPrivacySettings: { opened = true },
            onDismiss: { dismissed = true }
        )
        try view.inspect().find(button: "Open Privacy settings").tap()
        #expect(opened, "Tapping the primary action must open Settings")
        #expect(dismissed, "...and must also dismiss the sheet so it doesn't linger")
    }

    @Test("Version string is rendered into the header")
    func renderedVersion() throws {
        let view = ReleaseNotesModal(
            version: "9.9.9",
            onOpenPrivacySettings: {},
            onDismiss: {}
        )
        let texts = try view.inspect().findAll(ViewType.Text.self)
        let strings = texts.compactMap { try? $0.string() }
        #expect(strings.contains { $0.contains("9.9.9") },
                "The header must surface the version so users know what's new")
    }
}
