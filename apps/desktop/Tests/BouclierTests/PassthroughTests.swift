import Foundation
import Testing
@testable import Bouclier

/// Pins two SSRF/self-loop guards shared by the gateway and the
/// secret-keeper's host validation.
///
/// Cloud metadata IPs (169.254.169.254, metadata.google.internal,
/// metadata.azure.com) are kept blocked because there's no legitimate
/// use for them and they're the classic SSRF jackpot. Loopback hosts are
/// excluded from corporate-proxy detection so the gateway process itself
/// (which inherits `HTTPS_PROXY=http://127.0.0.1:<port>` once
/// `ShellEnvInjector` plants it) never tries to relay its own upstream
/// connections through itself.
@Suite("Proxy passthrough — SSRF/self-loop guards", .serialized)
@MainActor
struct PassthroughTests {
    @Test("Cloud-metadata hosts are recognized as never-tunnel targets")
    func cloudMetadataBlocked() {
        #expect(NetworkGuards.isCloudMetadataHost("169.254.169.254"))
        #expect(NetworkGuards.isCloudMetadataHost("metadata.google.internal"))
        #expect(NetworkGuards.isCloudMetadataHost("METADATA.AZURE.COM"))
        #expect(!NetworkGuards.isCloudMetadataHost("api.openai.com"))
        #expect(!NetworkGuards.isCloudMetadataHost("github.com"))
    }

    /// `ShellEnvInjector` plants `HTTPS_PROXY=http://127.0.0.1:8484`
    /// via `launchctl setenv`, so the Bouclier process itself inherits
    /// it on launch. If `CorporateProxy.detect()` honoured that env,
    /// the gateway would route every upstream connection *through
    /// itself* — an instant TLS-handshake loop that silently times out
    /// every API call. Caught during live-app QA; this pins the fix.
    @Test("CorporateProxy.detect ignores loopback hosts to prevent self-tunnelling")
    func corporateProxyIgnoresLoopback() {
        #expect(CorporateProxy.isLoopbackHost("127.0.0.1"))
        #expect(CorporateProxy.isLoopbackHost("localhost"))
        #expect(CorporateProxy.isLoopbackHost("LOCALHOST"))
        #expect(CorporateProxy.isLoopbackHost("127.42.0.1"))
        #expect(CorporateProxy.isLoopbackHost("::1"))
        #expect(!CorporateProxy.isLoopbackHost("proxy.corp.example.com"))
        #expect(!CorporateProxy.isLoopbackHost("10.0.0.5"))
    }
}
