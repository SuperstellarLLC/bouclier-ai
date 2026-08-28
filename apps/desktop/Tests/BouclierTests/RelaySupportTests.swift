import Foundation
import Testing
@testable import Bouclier

/// Pure-logic coverage for the transient passthrough relay. The spawn /
/// reclaim path drives real processes and is exercised by hand; here we
/// pin the parsing and liveness primitives it is built on.
@Suite("Passthrough relay — pidfile + liveness")
struct RelaySupportTests {

    @Test("Parses a well-formed pid\\nport pidfile")
    func parsesValid() {
        let info = RelaySupport.parsePidfile("4321\n8484\n")
        #expect(info == RelaySupport.RelayInfo(pid: 4321, port: 8484))
    }

    @Test("Tolerates surrounding whitespace")
    func tolerantOfWhitespace() {
        let info = RelaySupport.parsePidfile("  4321  \n  8484  ")
        #expect(info?.pid == 4321)
        #expect(info?.port == 8484)
    }

    @Test("Rejects malformed pidfiles rather than guessing")
    func rejectsMalformed() {
        #expect(RelaySupport.parsePidfile("") == nil)
        #expect(RelaySupport.parsePidfile("4321") == nil)          // no port line
        #expect(RelaySupport.parsePidfile("notapid\n8484") == nil)  // non-numeric pid
        #expect(RelaySupport.parsePidfile("4321\nnotaport") == nil) // non-numeric port
        #expect(RelaySupport.parsePidfile("0\n8484") == nil)        // process-group signal
        #expect(RelaySupport.parsePidfile("-1\n8484") == nil)       // broad process-set signal
        #expect(RelaySupport.parsePidfile("1\n8484") == nil)        // launchd is never our child
        #expect(RelaySupport.parsePidfile("4321\n0") == nil)
        #expect(RelaySupport.parsePidfile("4321\n65536") == nil)
        #expect(RelaySupport.parsePidfile("4321\n8484\nnot-a-uuid") == nil)
        #expect(RelaySupport.parsePidfile("4321\n8484\nextra\nfield") == nil)
    }

    @Test("Parses and retains a tokenized relay identity")
    func tokenizedIdentity() {
        let token = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
        let info = RelaySupport.parsePidfile("4321\n8484\n\(token)\n")
        #expect(info == RelaySupport.RelayInfo(pid: 4321, port: 8484, token: token))
    }

    @Test("A reused PID is not accepted without exact executable, port, and token")
    func commandIdentity() {
        let token = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
        let executable = "/Applications/Bouclier-ai.app/Contents/MacOS/Bouclier"
        let info = RelaySupport.RelayInfo(pid: 4321, port: 8484, token: token)

        #expect(RelaySupport.commandLineIdentifiesRelay(
            "\(executable) --relay 8484 --relay-token \(token)",
            info: info,
            expectedExecutablePath: executable
        ))
        #expect(!RelaySupport.commandLineIdentifiesRelay(
            "/usr/bin/sleep 900",
            info: info,
            expectedExecutablePath: executable
        ))
        #expect(!RelaySupport.commandLineIdentifiesRelay(
            "\(executable) --relay 8485 --relay-token \(token)",
            info: info,
            expectedExecutablePath: executable
        ))
        #expect(!RelaySupport.commandLineIdentifiesRelay(
            "\(executable) --relay 8484 --relay-token 00000000-0000-0000-0000-000000000000",
            info: info,
            expectedExecutablePath: executable
        ))
    }

    @Test("isAlive is true for this process, false for a reaped PID")
    func liveness() {
        #expect(RelaySupport.isAlive(getpid()) == true)
        // PID 1 (launchd) always exists; a very high PID reliably does not.
        #expect(RelaySupport.isAlive(999_999) == false)
    }
}
