import Foundation
import Testing
@testable import Bouclier

/// Pins the contract that `ProxyManager` initialises its storage and
/// auto-start side effects at *construction* time, not on first
/// menubar-open. The earlier design deferred this to
/// `MenuBarView.onAppear`, which only fires when the user clicks the
/// menubar icon — so the shield rendered "off" at launch and the
/// auto-start-when-CA-installed change was effectively a no-op until
/// the user happened to interact. The QA pass against the installed
/// app caught it; this test pins the fix so it can't regress silently.
@Suite("ProxyManager lifecycle", .serialized)
@MainActor
struct ProxyManagerLifecycleTests {
    @Test("initializeStorage runs at construction, not deferred to first menu open")
    func initRanAtConstruction() {
        let pm = ProxyManager()
        #expect(pm.didInitializeStorage,
                "ProxyManager.init() must call initializeStorage() so the menubar shield reflects state at launch — not after the user happens to click the menu")
    }
}
