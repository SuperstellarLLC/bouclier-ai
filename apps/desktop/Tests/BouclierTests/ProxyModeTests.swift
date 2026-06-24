import Foundation
import Testing
@testable import Bouclier

@Suite("ProxyMode — resolution", .serialized)
struct ProxyModeTests {
    @Test("Default is standard (non-CA; extreme is never implicit)")
    func defaultStandard() {
        ProxyMode.setTestOverride(nil)
        UserDefaults.standard.removeObject(forKey: ProxyMode.userDefaultsKey)
        #expect(ProxyMode.current == .standard)
        #expect(ProxyMode.compileDefault == .standard)
    }

    @Test("User must explicitly opt into extreme")
    func userDefaultExtreme() {
        ProxyMode.setTestOverride(nil)
        UserDefaults.standard.set("extreme", forKey: ProxyMode.userDefaultsKey)
        defer { UserDefaults.standard.removeObject(forKey: ProxyMode.userDefaultsKey) }
        #expect(ProxyMode.current == .extreme)
    }

    @Test("Test override wins over everything")
    func overrideWins() {
        UserDefaults.standard.set("standard", forKey: ProxyMode.userDefaultsKey)
        ProxyMode.setTestOverride(.extreme)
        defer {
            ProxyMode.setTestOverride(nil)
            UserDefaults.standard.removeObject(forKey: ProxyMode.userDefaultsKey)
        }
        #expect(ProxyMode.current == .extreme)
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

    @Test("Generated POSIX env script probes the gateway port for fail-open")
    func failOpenProbe() {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 9191)
        let script = ShellEnvInjector.posixEnvFileContent(exports: exports)
        #expect(script.contains("127.0.0.1 9191"))
        #expect(script.contains("ANTHROPIC_BASE_URL"))
        // Fail-open: unsets the vars when the gateway isn't listening.
        #expect(script.contains("unset"))
    }
}
