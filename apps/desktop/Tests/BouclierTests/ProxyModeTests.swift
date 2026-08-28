import Foundation
import Testing
@testable import Bouclier

@Suite("ProxyMode — resolution", .serialized)
struct ProxyModeTests {
    @Test("Standard is the only mode, and the default")
    func defaultStandard() {
        ProxyMode.setTestOverride(nil)
        UserDefaults.standard.removeObject(forKey: ProxyMode.userDefaultsKey)
        #expect(ProxyMode.current == .standard)
        #expect(ProxyMode.compileDefault == .standard)
        #expect(ProxyMode.allCases == [.standard])
    }

    @Test("A stale 'extreme' value from a pre-removal install falls back to standard")
    func staleExtremeValueFallsBack() {
        ProxyMode.setTestOverride(nil)
        UserDefaults.standard.set("extreme", forKey: ProxyMode.userDefaultsKey)
        defer { UserDefaults.standard.removeObject(forKey: ProxyMode.userDefaultsKey) }
        #expect(ProxyMode.current == .standard)
    }

    @Test("Test override wins over everything")
    func overrideWins() {
        UserDefaults.standard.set("standard", forKey: ProxyMode.userDefaultsKey)
        ProxyMode.setTestOverride(.standard)
        defer {
            ProxyMode.setTestOverride(nil)
            UserDefaults.standard.removeObject(forKey: ProxyMode.userDefaultsKey)
        }
        #expect(ProxyMode.current == .standard)
    }
}

@Suite("ShellEnvInjector — standard-mode exports")
struct StandardExportsTests {
    @Test("Standard mode sets base-URL vars only — never HTTPS_PROXY or CA vars")
    func baseURLOnly() {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 8585)
        let dict = Dictionary(exports.pairs, uniquingKeysWith: { a, _ in a })
        #expect(dict["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8585")
        #expect(dict["OPENAI_BASE_URL"] == "http://127.0.0.1:8585/v1")
        // The critical safety property: standard mode must NOT route all
        // HTTPS through the gateway (it isn't a CONNECT proxy) and must NOT
        // plant CA-trust vars (no Bouclier cert exists in this mode).
        #expect(dict["HTTPS_PROXY"] == nil)
        #expect(dict["HTTP_PROXY"] == nil)
        #expect(dict["NODE_EXTRA_CA_CERTS"] == nil)
        #expect(dict["SSL_CERT_FILE"] == nil)
    }

    @Test("Generated POSIX env script probes Bouclier liveness for fail-open")
    func failOpenProbe() {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 9191)
        let script = ShellEnvInjector.posixEnvFileContent(exports: exports)
        #expect(script.contains("http://127.0.0.1:9191/livez"))
        #expect(script.contains("ANTHROPIC_BASE_URL"))
        // Fail-open: unsets the vars when the gateway isn't listening.
        #expect(script.contains("unset"))
    }
}
