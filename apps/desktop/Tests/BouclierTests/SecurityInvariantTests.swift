import Foundation
import Testing
@testable import Bouclier

/// Regression tests for the security invariants surfaced by the
/// S-tier audit pass. Each test pins down a concrete attack we
/// promised to defend against — if any of these flip green-to-red,
/// a real attack surface has been re-opened.
@Suite("Security invariants")
struct SecurityInvariantTests {
    // MARK: - HTTP request smuggling

    @Test("Header values carrying CR/LF/NUL are detected")
    func headerValueControlBytesDetected() {
        #expect(HTTPRequestInspector.containsControlBytes("normal value") == false)
        #expect(HTTPRequestInspector.containsControlBytes("bad\r\nX-Smuggled: yes"))
        #expect(HTTPRequestInspector.containsControlBytes("bad\nfoo"))
        #expect(HTTPRequestInspector.containsControlBytes("bad\rfoo"))
        #expect(HTTPRequestInspector.containsControlBytes("bad\0null"))
    }

    @Test("Header names match the RFC 7230 token grammar")
    func headerNameTokenGrammar() {
        #expect(HTTPRequestInspector.isValidHeaderName("Content-Type"))
        #expect(HTTPRequestInspector.isValidHeaderName("X-Custom-1"))
        #expect(HTTPRequestInspector.isValidHeaderName("Accept"))
        // Empty, whitespace, separators, CTLs — all rejected.
        #expect(HTTPRequestInspector.isValidHeaderName("") == false)
        #expect(HTTPRequestInspector.isValidHeaderName("Bad Header") == false)
        #expect(HTTPRequestInspector.isValidHeaderName("Bad:Header") == false)
        #expect(HTTPRequestInspector.isValidHeaderName("Bad\rHeader") == false)
        #expect(HTTPRequestInspector.isValidHeaderName("Bad\nHeader") == false)
        #expect(HTTPRequestInspector.isValidHeaderName("Bad\0Header") == false)
    }

    // MARK: - CONNECT target

    @Test("CONNECT parser rejects CRLF and NUL bytes")
    func connectParserRejectsControlBytes() {
        #expect(HTTPRequestInspector.parseConnectTarget("api.openai.com:443") != nil)
        #expect(HTTPRequestInspector.parseConnectTarget("api.openai.com:443\r\nHost: x") == nil)
        #expect(HTTPRequestInspector.parseConnectTarget("api.openai.com:443\0") == nil)
        #expect(HTTPRequestInspector.parseConnectTarget(" api.openai.com:443") == nil)
        #expect(HTTPRequestInspector.parseConnectTarget("api.openai.com:99999") == nil)
    }

    // MARK: - SSE stream cap

    @Test("SSE inspector closes when the unflushed buffer crosses the cap")
    func sseBufferCap() {
        let filter = InjectionFilter()
        let inspector = SSEStreamInspector(filter: filter)
        // Feed > maxBufferBytes worth of bytes WITHOUT an event
        // terminator, simulating a runaway upstream. The inspector
        // should close with the oversize frame.
        let oversize = String(repeating: "a", count: SSEStreamInspector.maxBufferBytes + 1024)
        let out = inspector.ingest(oversize)
        #expect(inspector.closed)
        #expect(out.contains("sse_buffer_exceeded"))
    }

    @Test("SSE inspector tolerates normal-sized frames")
    func sseNormalFrame() {
        let filter = InjectionFilter()
        let inspector = SSEStreamInspector(filter: filter)
        let frame = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"
        let out = inspector.ingest(frame)
        #expect(!inspector.closed)
        #expect(out.contains("hi"))
    }
}
