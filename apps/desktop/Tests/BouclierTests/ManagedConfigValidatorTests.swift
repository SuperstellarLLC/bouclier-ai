import Foundation
import Testing
@testable import Bouclier

@Suite("ManagedConfigValidator")
struct ManagedConfigValidatorTests {
    // MARK: - Ports

    @Test("Accepts unprivileged ports")
    func acceptsUnprivileged() {
        #expect(ManagedConfigValidator.validatedPort(8484) == 8484)
        #expect(ManagedConfigValidator.validatedPort(65535) == 65535)
        #expect(ManagedConfigValidator.validatedPort(1024) == 1024)
    }

    @Test("Rejects privileged, zero, negative, or oversized ports")
    func rejectsBadPorts() {
        #expect(ManagedConfigValidator.validatedPort(80) == nil)
        #expect(ManagedConfigValidator.validatedPort(443) == nil)
        #expect(ManagedConfigValidator.validatedPort(0) == nil)
        #expect(ManagedConfigValidator.validatedPort(-1) == nil)
        #expect(ManagedConfigValidator.validatedPort(70000) == nil)
        #expect(ManagedConfigValidator.validatedPort(nil) == nil)
    }

    @Test("Accepts only documented enforcement policies")
    func validatesEnforcementPolicy() {
        #expect(ManagedConfigValidator.validatedEnforcementPolicy("BLOCK") == "block")
        #expect(ManagedConfigValidator.validatedEnforcementPolicy("monitor") == "monitor")
        #expect(ManagedConfigValidator.validatedEnforcementPolicy("warn") == "warn")
        #expect(ManagedConfigValidator.validatedEnforcementPolicy("log") == "log")
        #expect(ManagedConfigValidator.validatedEnforcementPolicy("allow") == nil)
        #expect(ManagedConfigValidator.validatedEnforcementPolicy(nil) == nil)
    }

    // MARK: - Hostnames

    @Test("Accepts standard hostnames")
    func acceptsHostnames() {
        #expect(ManagedConfigValidator.validatedHostname("api.openai.com") == "api.openai.com")
        #expect(ManagedConfigValidator.validatedHostname("API.OpenAI.COM") == "api.openai.com")
        #expect(ManagedConfigValidator.validatedHostname("api-v2.custom.ai") == "api-v2.custom.ai")
    }

    @Test("Rejects wildcards, empty labels, paths, and whitespace")
    func rejectsBadHostnames() {
        #expect(ManagedConfigValidator.validatedHostname("") == nil)
        #expect(ManagedConfigValidator.validatedHostname("*") == nil)
        #expect(ManagedConfigValidator.validatedHostname("*.openai.com") == nil)
        #expect(ManagedConfigValidator.validatedHostname("api..openai.com") == nil)
        #expect(ManagedConfigValidator.validatedHostname("api.openai.com/admin") == nil)
        #expect(ManagedConfigValidator.validatedHostname("api openai.com") == nil)
        #expect(ManagedConfigValidator.validatedHostname("api.openai.com\r\nX: y") == nil)
        #expect(ManagedConfigValidator.validatedHostname("-api.openai.com") == nil)
        #expect(ManagedConfigValidator.validatedHostname("api.openai.com-") == nil)
        #expect(ManagedConfigValidator.validatedHostname("[::1]") == nil)
        #expect(ManagedConfigValidator.validatedHostname("169.254.169.254") == "169.254.169.254")
        // IPv4 literals pass the label test (digits + dots). They are
        // still rejected at the allowlist layer because built-in domains
        // are all hostnames.
    }

    @Test("Filters a mixed MDM domain list")
    func filtersDomainList() {
        let raw = [
            "api.openai.com",
            "",
            "*.evil.com",
            "api.custom.ai",
            "api.custom.ai/admin",
            "good.example.com",
            "bad example.com",
        ]
        let filtered = ManagedConfigValidator.validatedHostnames(raw)
        #expect(filtered.contains("api.openai.com"))
        #expect(filtered.contains("api.custom.ai"))
        #expect(filtered.contains("good.example.com"))
        #expect(!filtered.contains(""))
        #expect(!filtered.contains("*.evil.com"))
        #expect(!filtered.contains("api.custom.ai/admin"))
        #expect(!filtered.contains("bad example.com"))
        #expect(filtered.count == 3)
    }

    // MARK: - Webhook URLs

    @Test("Accepts https webhook URLs")
    func acceptsHTTPSWebhook() {
        let url = ManagedConfigValidator.validatedWebhookURL("https://siem.corp.com/bouclier")
        #expect(url?.absoluteString == "https://siem.corp.com/bouclier")
    }

    @Test("Rejects non-https webhook URLs")
    func rejectsNonHTTPSWebhook() {
        #expect(ManagedConfigValidator.validatedWebhookURL("http://siem.corp.com/i") == nil)
        #expect(ManagedConfigValidator.validatedWebhookURL("file:///tmp/exfil.json") == nil)
        #expect(ManagedConfigValidator.validatedWebhookURL("javascript:alert(1)") == nil)
        #expect(ManagedConfigValidator.validatedWebhookURL("ftp://example.com") == nil)
        #expect(ManagedConfigValidator.validatedWebhookURL(nil) == nil)
        #expect(ManagedConfigValidator.validatedWebhookURL("") == nil)
    }

    @Test("Rejects webhook URLs with fragments")
    func rejectsFragment() {
        #expect(ManagedConfigValidator.validatedWebhookURL("https://siem.corp.com/i#frag") == nil)
    }

}
