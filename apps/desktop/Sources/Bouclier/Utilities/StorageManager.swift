import Foundation
import GRDB

/// Manages local SQLite storage for scan logs and daily stats.
/// Uses GRDB with WAL mode for concurrent reads during proxy operation.
final class StorageManager: @unchecked Sendable {
    private let dbPool: DatabasePool
    /// Background task running the daily cleanup cadence. Held so the
    /// task is cancelled when the storage manager is torn down (tests,
    /// re-init, etc.).
    private var retentionTask: Task<Void, Never>?

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    init() throws {
        guard let appSupportDir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw StorageError.noAppSupportDirectory
        }
        let supportDir = appSupportDir.appendingPathComponent("ai.bouclier.app", isDirectory: true)

        try FileManager.default.createDirectory(at: supportDir, withIntermediateDirectories: true)

        let dbPath = supportDir.appendingPathComponent("bouclier-ai.sqlite").path
        dbPool = try DatabasePool(path: dbPath)

        try migrate()
        try cleanup()
        startRetentionTask()
    }

    deinit {
        retentionTask?.cancel()
    }

    /// Drive cleanup once every 24 h while the app is running.
    /// Without this, retention only applied at launch — a process kept
    /// running for weeks would grow the audit DB indefinitely.
    private func startRetentionTask() {
        retentionTask = Task.detached(priority: .background) { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 24 * 3600 * 1_000_000_000)
                guard !Task.isCancelled, let self else { return }
                try? self.cleanup()
            }
        }
    }

    // MARK: - Schema

    private func migrate() throws {
        var migrator = DatabaseMigrator()

        migrator.registerMigration("v1") { db in
            try db.create(table: "scan_logs") { t in
                t.autoIncrementedPrimaryKey("id")
                // The parentheses are load-bearing: SQLite only accepts an
                // expression default in CREATE TABLE as `DEFAULT (expr)`,
                // and GRDB emits the `defaults(sql:)` string verbatim.
                // Unparenthesized, this migration is a syntax error — v1
                // throws, grdb_migrations stays empty, and (because init
                // failures were swallowed) no install ever had a scan_logs
                // table until this was fixed.
                t.column("timestamp", .text).notNull().defaults(sql: "(datetime('now'))")
                t.column("source", .text).notNull()           // 'api-proxy' | 'mcp-proxy'
                t.column("targetHost", .text)
                t.column("detected", .integer).notNull()       // 0 or 1
                t.column("matchCount", .integer).notNull().defaults(to: 0)
                t.column("patternIds", .text)                  // JSON array
                t.column("severity", .text)
                t.column("requestSize", .integer)
            }

            try db.create(table: "daily_stats") { t in
                t.primaryKey("date", .text)                    // '2026-04-04'
                t.column("requestsScanned", .integer).defaults(to: 0)
                t.column("injectionsBlocked", .integer).defaults(to: 0)
            }

            try db.create(
                indexOn: "scan_logs",
                columns: ["timestamp"]
            )
            try db.create(
                indexOn: "scan_logs",
                columns: ["detected"]
            )
        }

        // v2 — fused-scoring telemetry. ML classifier (Prompt Guard 2)
        // and entropy heuristic now contribute to detection alongside
        // regex; persist their per-request scores so the dashboard can
        // surface why a request was blocked, and so we can tune the
        // fused thresholds against real traffic later.
        migrator.registerMigration("v2") { db in
            try db.alter(table: "scan_logs") { t in
                t.add(column: "mlScore", .double)              // 0..1, NULL when ML unavailable
                t.add(column: "entropyAnomaly", .double).notNull().defaults(to: 0)
                t.add(column: "fusedScore", .double).notNull().defaults(to: 0)
                t.add(column: "mlAvailable", .integer).notNull().defaults(to: 0)
            }
        }

        // v3 — PII redaction audit log. Each row records ONE substituted
        // entity. Stores entity type and char offsets only; NEVER stores
        // cleartext. The valueHashPrefix is the first 4 bytes of SHA-256
        // of the cleartext — enough to recognize the same value reused
        // in a session, useless to anyone scraping the DB.
        migrator.registerMigration("v3_pii_redactions") { db in
            try db.create(table: "pii_redactions") { t in
                t.autoIncrementedPrimaryKey("id")
                // Parenthesized for the same SQLite grammar reason as v1.
                t.column("timestamp", .text).notNull().defaults(sql: "(datetime('now'))")
                t.column("targetHost", .text)
                t.column("entityType", .text).notNull()    // EMAIL, IBAN, FR_NIR, etc.
                t.column("startOffset", .integer).notNull()
                t.column("endOffset", .integer).notNull()
                t.column("valueHashPrefix", .text).notNull()
                t.column("scanLogId", .integer)
                    .references("scan_logs", onDelete: .cascade)
            }
            try db.create(indexOn: "pii_redactions", columns: ["timestamp"])
            try db.create(indexOn: "pii_redactions", columns: ["entityType"])
        }

        // v4 — scope-cut purge. Pre-v0.6 Bouclier redacted text prompt
        // bodies, so existing rows have `startOffset` / `endOffset`
        // defined against request-body byte positions. v0.6 only writes
        // rows for PII found *inside file attachments*, where those
        // offsets carry no meaning (always 0/0). Mixing the two would
        // make the audit panel and the exported PDF dishonest — counts
        // would aggregate two semantic universes. Wipe the table once
        // on upgrade so every row a user sees from this point forward
        // is from the file-inspection path.
        migrator.registerMigration("v4_scope_cut_purge_prompt_pii_rows") { db in
            try db.execute(sql: "DELETE FROM pii_redactions")
        }

        try migrator.migrate(dbPool)
    }

    // MARK: - PII audit

    /// One row destined for the `pii_redactions` table. Lets callers
    /// batch a request's worth of redactions into a single transaction
    /// instead of N round-trips through `dbPool.write`.
    struct PIIRedactionRow: Sendable {
        let targetHost: String?
        let entityType: String
        let startOffset: Int
        let endOffset: Int
        let valueHashPrefix: String
        let scanLogId: Int64?
    }

    /// Record one PII redaction event. Convenience wrapper around the
    /// batch form for single-row callers.
    func recordPIIRedaction(
        targetHost: String?,
        entityType: String,
        startOffset: Int,
        endOffset: Int,
        valueHashPrefix: String,
        scanLogId: Int64?
    ) {
        recordPIIRedactions([
            PIIRedactionRow(
                targetHost: targetHost, entityType: entityType,
                startOffset: startOffset, endOffset: endOffset,
                valueHashPrefix: valueHashPrefix, scanLogId: scanLogId
            )
        ])
    }

    /// Batch-insert N redaction rows in a single SQLite transaction.
    /// A request with 50 detected entities goes from 50 commits to 1.
    func recordPIIRedactions(_ rows: [PIIRedactionRow]) {
        guard !rows.isEmpty else { return }
        do {
            try dbPool.write { db in
                let stmt = try db.makeStatement(sql: """
                    INSERT INTO pii_redactions
                        (targetHost, entityType, startOffset, endOffset, valueHashPrefix, scanLogId)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """)
                for row in rows {
                    try stmt.execute(arguments: [
                        row.targetHost, row.entityType,
                        row.startOffset, row.endOffset,
                        row.valueHashPrefix, row.scanLogId,
                    ])
                }
            }
        } catch {
            print("[bouclier.ai-storage] PII audit write error: \(error.localizedDescription)")
        }
    }

    /// Aggregate counts of PII redactions by entity type within the
    /// given window. Powers the audit-log row in Settings without
    /// exposing per-event details.
    func piiRedactionCounts(days: Int = 30) -> [String: Int] {
        let rows = (try? dbPool.read { db -> [Row] in
            try Row.fetchAll(
                db,
                sql: """
                    SELECT entityType, COUNT(*) as count
                    FROM pii_redactions
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY entityType
                    """,
                arguments: ["-\(days) days"]
            )
        }) ?? []
        var out: [String: Int] = [:]
        for row in rows {
            if let type: String = row["entityType"], let count: Int = row["count"] {
                out[type] = count
            }
        }
        return out
    }

    /// Aggregate counts of PII redactions by destination host within
    /// the given window. Used by the redaction report so a compliance
    /// officer can see which upstream provider received how many
    /// redacted prompts.
    func piiRedactionCountsByHost(days: Int = 30) -> [String: Int] {
        let rows = (try? dbPool.read { db -> [Row] in
            try Row.fetchAll(
                db,
                sql: """
                    SELECT targetHost, COUNT(*) as count
                    FROM pii_redactions
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY targetHost
                    """,
                arguments: ["-\(days) days"]
            )
        }) ?? []
        var out: [String: Int] = [:]
        for row in rows {
            if let host: String = row["targetHost"], let count: Int = row["count"] {
                out[host] = count
            }
        }
        return out
    }

    /// Total count of PII redaction events in the window, plus the
    /// total count of prompts scanned (across all detection types) so
    /// the report can compute a "X redactions across Y prompts" ratio.
    func piiRedactionTotals(days: Int = 30) -> (redactions: Int, prompts: Int) {
        let red = (try? dbPool.read { db -> Int in
            try Int.fetchOne(
                db,
                sql: "SELECT COUNT(*) FROM pii_redactions WHERE timestamp >= datetime('now', ?)",
                arguments: ["-\(days) days"]
            ) ?? 0
        }) ?? 0
        let prompts = (try? dbPool.read { db -> Int in
            try Int.fetchOne(
                db,
                sql: "SELECT COUNT(*) FROM scan_logs WHERE timestamp >= datetime('now', ?)",
                arguments: ["-\(days) days"]
            ) ?? 0
        }) ?? 0
        return (red, prompts)
    }

    // MARK: - Write

    /// Record a scan event.
    func recordScan(
        source: String,
        targetHost: String,
        detected: Bool,
        matchCount: Int,
        patternIds: [String],
        severity: String?,
        requestSize: Int,
        mlScore: Float?,
        entropyAnomaly: Double,
        fusedScore: Double,
        mlAvailable: Bool
    ) {
        do {
            try dbPool.write { db in
                try db.execute(
                    sql: """
                        INSERT INTO scan_logs (
                            source, targetHost, detected, matchCount, patternIds, severity, requestSize,
                            mlScore, entropyAnomaly, fusedScore, mlAvailable
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    arguments: [
                        source,
                        targetHost,
                        detected ? 1 : 0,
                        matchCount,
                        String(data: try JSONSerialization.data(withJSONObject: patternIds), encoding: .utf8) ?? "[]",
                        severity,
                        requestSize,
                        mlScore.map { Double($0) },
                        entropyAnomaly,
                        fusedScore,
                        mlAvailable ? 1 : 0,
                    ]
                )

                // Update daily stats. `injectionsBlocked` counts only
                // requests that were actually refused, and mirrors the
                // in-memory `stats.injectionsBlocked` increment exactly:
                //   - monitor mode / forwarded (detected == false): +0.
                //     Previously this added `matchCount`, so a flagged-but-
                //     forwarded request with pattern hits inflated the
                //     "blocked" figure — a request that was never blocked.
                //   - an ML/entropy-only block (detected, matchCount 0):
                //     +1, so it isn't undercounted to zero.
                //   - a regex block: +matchCount.
                let blockedIncrement = detected ? max(1, matchCount) : 0
                let today = Self.todayString()
                try db.execute(
                    sql: """
                        INSERT INTO daily_stats (date, requestsScanned, injectionsBlocked)
                        VALUES (?, 1, ?)
                        ON CONFLICT(date) DO UPDATE SET
                            requestsScanned = requestsScanned + 1,
                            injectionsBlocked = injectionsBlocked + ?
                        """,
                    arguments: [today, blockedIncrement, blockedIncrement]
                )
            }
        } catch {
            // Log but don't crash the proxy
            print("[bouclier.ai-storage] Write error: \(error.localizedDescription)")
        }
    }

    // MARK: - Read

    /// Fetch recent scan logs.
    func recentLogs(limit: Int = 100) -> [ScanLogRow] {
        (try? dbPool.read { db in
            try ScanLogRow.fetchAll(
                db,
                sql: "SELECT * FROM scan_logs ORDER BY timestamp DESC LIMIT ?",
                arguments: [limit]
            )
        }) ?? []
    }

    /// Fetch today's stats.
    func todayStats() -> DailyStatsRow? {
        try? dbPool.read { db in
            try DailyStatsRow.fetchOne(
                db,
                sql: "SELECT * FROM daily_stats WHERE date = ?",
                arguments: [Self.todayString()]
            )
        }
    }

    /// Fetch stats for the last N days.
    func statsHistory(days: Int = 30) -> [DailyStatsRow] {
        (try? dbPool.read { db in
            try DailyStatsRow.fetchAll(
                db,
                sql: "SELECT * FROM daily_stats ORDER BY date DESC LIMIT ?",
                arguments: [days]
            )
        }) ?? []
    }

    // MARK: - Cleanup

    /// Remove logs older than 30 days, stats older than 365 days. PII
    /// redaction audit retained for 30 days (configurable later via MDM);
    /// shorter than scan logs so PII fingerprints don't outlive their
    /// useful debugging window.
    private func cleanup() throws {
        try dbPool.write { db in
            try db.execute(sql: "DELETE FROM scan_logs WHERE timestamp < datetime('now', '-30 days')")
            try db.execute(sql: "DELETE FROM daily_stats WHERE date < date('now', '-365 days')")
            // pii_redactions cascades from scan_logs but also has an
            // explicit retention so events without a parent scan
            // (proxy-bypassed paths) are cleaned up too.
            try db.execute(sql: "DELETE FROM pii_redactions WHERE timestamp < datetime('now', '-30 days')")
        }
    }

    // MARK: - Helpers

    private static func todayString() -> String {
        dateFormatter.string(from: Date())
    }

    enum StorageError: Error {
        case noAppSupportDirectory
    }
}

// MARK: - Row Types

struct ScanLogRow: FetchableRecord, Codable, Sendable {
    let id: Int64
    let timestamp: String
    let source: String
    let targetHost: String?
    let detected: Int
    let matchCount: Int
    let patternIds: String?
    let severity: String?
    let requestSize: Int?
    // Added in v2 — fused scoring telemetry.
    let mlScore: Double?
    let entropyAnomaly: Double
    let fusedScore: Double
    let mlAvailable: Int
}

struct DailyStatsRow: FetchableRecord, Codable, Sendable {
    let date: String
    let requestsScanned: Int
    let injectionsBlocked: Int
}
