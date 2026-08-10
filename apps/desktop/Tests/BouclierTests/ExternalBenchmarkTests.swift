import Foundation
import Testing
@testable import Bouclier

/// Opt-in external benchmark of the SHIPPED detection pipeline against
/// third-party corpora — not Bouclier's own pattern examples. Runs the real
/// fused path (regex + dampeners + Prompt Guard 2 CoreML, if the model is
/// present) through `InjectionInspectionPass.inspect`, exactly as the gateway
/// does, with each corpus string wrapped as an untrusted `tool_result` span.
///
/// Gated behind `BOUCLIER_BENCH=1` and the presence of the corpus files
/// (fetched by `benchmark/fetch-corpora.py`), so a normal `swift test` and CI
/// skip it entirely.
///
/// IMPORTANT interpretive caveat, stated in the output: the deepset corpus
/// labels DIRECT jailbreak/role-play prompts as "injection". Bouclier targets
/// INDIRECT injection (attacker instructions in tool output) and, by design,
/// never blocks the operator's own text. Wrapping every string as tool_result
/// measures the engine's raw detection capability on external strings — a fair
/// test of the classifier/patterns, but a low score partly reflects a
/// threat-model mismatch (jailbreak != indirect injection), not only recall.
@Suite("External benchmark (opt-in)", .enabled(if: ProcessInfo.processInfo.environment["BOUCLIER_BENCH"] == "1"))
struct ExternalBenchmarkTests {
    static let repoDesktop = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // BouclierTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // desktop
    static let dataDir = repoDesktop.appendingPathComponent("benchmark/data")
    static let patternsURL = repoDesktop.appendingPathComponent("Sources/Bouclier/Resources/patterns.json")

    struct Item: Decodable { let text: String; let label: String; let src: String? }

    private func load(_ name: String) -> [Item] {
        guard let data = try? Data(contentsOf: Self.dataDir.appendingPathComponent(name)),
              let s = String(data: data, encoding: .utf8) else { return [] }
        return s.split(separator: "\n").compactMap { line in
            guard let d = line.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(Item.self, from: d)
        }
    }

    private func toolResult(_ text: String) -> Data {
        try! JSONSerialization.data(withJSONObject: [
            "messages": [[
                "role": "user",
                "content": [["type": "tool_result", "tool_use_id": "t1", "content": text]],
            ]],
        ])
    }

    @Test("Benchmark the shipped fused pipeline on external corpora")
    func benchmark() async throws {
        let attacks = load("attacks.jsonl")
        let benign = load("benign.jsonl")
        try #require(!attacks.isEmpty && !benign.isEmpty,
                     "corpus files missing — run benchmark/fetch-corpora.py first")

        // Shipped config: full pattern set + dampeners, plus the CoreML ML
        // tier if the model loads (it ships in the DMG; may be absent in a
        // bare checkout, in which case this measures the regex+entropy path).
        let data = try Data(contentsOf: Self.patternsURL)
        let set = try JSONDecoder().decode(PatternSetJSON.self, from: data)
        let patterns = set.patterns.compactMap { FilterPattern(from: $0) }
        let dampeners = InjectionFilter.compileDampeners(set.dampeners ?? [])
        let classifier = try? await MLClassifier()
        let filter = InjectionFilter(patterns: patterns, dampeners: dampeners, classifier: classifier)
        let mlOn = filter.hasMLClassifier

        struct Tally { var n = 0, block = 0, flag = 0 }
        func run(_ items: [Item]) -> ([String: Tally], Tally) {
            var bySrc: [String: Tally] = [:]; var total = Tally()
            for it in items {
                let o = InjectionInspectionPass.inspect(body: toolResult(it.text), filter: filter)
                let src = it.src ?? "?"
                var t = bySrc[src] ?? Tally(); t.n += 1; total.n += 1
                switch o.decision {
                case .block: t.block += 1; total.block += 1
                case .flag:  t.flag += 1;  total.flag += 1
                case .allow: break
                }
                bySrc[src] = t
            }
            return (bySrc, total)
        }

        let (aSrc, aTot) = run(attacks)
        let (bSrc, bTot) = run(benign)

        func pct(_ x: Int, _ n: Int) -> String { n == 0 ? "—" : String(format: "%.1f%%", 100.0 * Double(x) / Double(n)) }

        var out = "\n===== Bouclier external benchmark =====\n"
        out += "engine: regex(\(patterns.count)) + dampeners(\(dampeners.count)) + ML:\(mlOn ? "Prompt Guard 2" : "OFF (regex/entropy only)")\n"
        out += "block threshold: \(InjectionInspectionPass.untrustedBlockThreshold) (untrusted); each item wrapped as tool_result\n\n"
        out += "ATTACKS (want high block/detect) — n=\(aTot.n)\n"
        for (s, t) in aSrc.sorted(by: { $0.key < $1.key }) {
            out += "  \(s): n=\(t.n)  blocked \(pct(t.block, t.n))  detected(block+flag) \(pct(t.block + t.flag, t.n))\n"
        }
        out += "  ALL: blocked \(pct(aTot.block, aTot.n))  detected \(pct(aTot.block + aTot.flag, aTot.n))\n\n"
        out += "BENIGN (want low block; warn=over-defense) — n=\(bTot.n)\n"
        for (s, t) in bSrc.sorted(by: { $0.key < $1.key }) {
            out += "  \(s): n=\(t.n)  blocked \(pct(t.block, t.n))  warned \(pct(t.flag, t.n))\n"
        }
        out += "  ALL: blocked \(pct(bTot.block, bTot.n))  warned \(pct(bTot.flag, bTot.n))\n"
        out += "\nNOTE: deepset labels direct jailbreak/role-play as injection; Bouclier targets\n"
        out += "indirect injection and never blocks principal text — see suite doc comment.\n"
        out += "=======================================\n"
        print(out)

        // Not an assertion suite — it measures. Keep one trivial expectation
        // so the run is recorded as passed once it completes.
        #expect(aTot.n > 0 && bTot.n > 0)
    }
}
