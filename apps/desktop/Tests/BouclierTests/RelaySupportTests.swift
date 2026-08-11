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
    }

    @Test("isAlive is true for this process, false for a reaped PID")
    func liveness() {
        #expect(RelaySupport.isAlive(getpid()) == true)
        // PID 1 (launchd) always exists; a very high PID reliably does not.
        #expect(RelaySupport.isAlive(999_999) == false)
    }
}
