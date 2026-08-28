import Foundation
import Testing
@testable import Bouclier
@testable import BouclierCore

@Suite("StatusPublisher — prompt state publication", .serialized)
@MainActor
struct StatusPublisherTests {
    @Test("refresh immediately replaces the published snapshot")
    func refreshWritesCurrentState() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("status-publisher-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let statusFile = directory.appendingPathComponent("status.json")

        var current = status(running: false, protectionEnabled: true)
        let publisher = StatusPublisher(statusFile: statusFile, snapshot: { current })
        defer { publisher.stop() }

        publisher.refresh()
        var decoded = try JSONDecoder().decode(
            BouclierStatus.self, from: Data(contentsOf: statusFile)
        )
        #expect(!decoded.running)
        #expect(!decoded.detectorEnabled)
        #expect(!decoded.blockingEnabled)

        current = status(running: true, protectionEnabled: true)
        publisher.refresh()
        decoded = try JSONDecoder().decode(
            BouclierStatus.self, from: Data(contentsOf: statusFile)
        )
        #expect(decoded.running)
        #expect(decoded.detectorEnabled)
        #expect(decoded.blockingEnabled)
    }

    @Test("stop removes the injected snapshot")
    func stopRemovesSnapshot() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("status-publisher-stop-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let statusFile = directory.appendingPathComponent("status.json")
        let publisher = StatusPublisher(
            statusFile: statusFile,
            snapshot: { status(running: true, protectionEnabled: true) }
        )

        publisher.refresh()
        #expect(FileManager.default.fileExists(atPath: statusFile.path))
        publisher.stop()
        #expect(!FileManager.default.fileExists(atPath: statusFile.path))
    }

    private func status(running: Bool, protectionEnabled: Bool) -> BouclierStatus {
        BouclierStatus(
            writtenAt: 123, pid: 7, appVersion: "test",
            running: running, mode: "standard", caInstalled: false,
            protectionEnabled: protectionEnabled,
            detectorEnabled: true, blockingEnabled: true,
            activity: .init(requestsScanned: 0, injectionsBlocked: 0)
        )
    }
}
