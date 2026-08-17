import Image from "next/image";
import Link from "next/link";
import { MobileNav } from "./mobile-nav";
import { Playground } from "./playground";
import { APP_VERSION, DOWNLOAD_URL, PATTERN_COUNT } from "@/lib/constants";

export default function Home() {
  return (
    <main className="min-h-screen">
      {/* ── Nav ──────────────────────────────────── */}
      <nav
        className="border-border sticky top-0 z-50 border-b bg-white/80 backdrop-blur-xl"
        aria-label="Main"
      >
        <div className="relative mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-center gap-2.5">
            <Image
              src="/images/logo-64.png"
              alt="Bouclier.ai"
              width={24}
              height={24}
              className="rounded-[5px]"
            />
            <span className="text-text text-[15px] font-semibold tracking-tight">Bouclier.ai</span>
            <span className="rounded-md border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-800">
              Beta
            </span>
          </Link>
          <div className="hidden items-center gap-6 sm:flex">
            <a
              href="#playground"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Live demo
            </a>
            <a
              href="#how"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              How it works
            </a>
            <a
              href="#benchmarks"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Benchmarks
            </a>
            <a
              href="#agents"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              For agents
            </a>
            <Link
              href="/privacy"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Privacy
            </Link>
            <Link
              href="/terms"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Terms
            </Link>
            <a
              href={DOWNLOAD_URL}
              className="bg-bouclier hover:bg-bouclier-dark rounded-lg px-4 py-2 text-sm font-medium text-white shadow-sm transition-all hover:shadow-md"
            >
              Download
            </a>
          </div>
          <MobileNav downloadUrl={DOWNLOAD_URL} />
        </div>
      </nav>

      {/* ── Hero ──────────────────────────────────── */}
      <section className="relative overflow-hidden">
        <div className="from-bouclier-light/50 absolute inset-0 bg-gradient-to-b to-white" />
        <div className="relative mx-auto max-w-5xl px-6 pb-24 pt-20 text-center">
          <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
            <div className="shield-ring border-bouclier/10 h-[500px] w-[500px] rounded-full border" />
          </div>
          <div className="pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
            <div className="shield-ring-delayed border-bouclier/15 h-[360px] w-[360px] rounded-full border" />
          </div>

          <div className="hero-recede relative">
            <div className="border-bouclier/20 text-bouclier mb-6 inline-flex items-center gap-2 rounded-full border bg-white px-4 py-1.5 text-sm font-medium shadow-sm">
              <span className="bg-accent-green h-1.5 w-1.5 rounded-full" />
              <span className="rounded-sm bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-800">
                Beta
              </span>
              v{APP_VERSION} — runs entirely on your Mac
            </div>

            <h1 className="text-text mx-auto max-w-3xl text-5xl font-bold leading-[1.1] tracking-tight sm:text-6xl">
              Web pages should not
              <br />
              <span className="text-bouclier">give your agents instructions.</span>
            </h1>

            <p className="text-text-secondary mx-auto mt-6 max-w-2xl text-lg leading-relaxed">
              Bouclier.ai is a prompt-injection firewall that runs on your Mac, between your coding
              agent and the model provider. It reads the content your agent pulls in from the
              outside — a fetched web page, a search result, an MCP response — and flags anything
              trying to reprogram it. It monitors by default; flip on blocking and it refuses those
              requests outright. Your own prompts, and the files you read from your own project, are
              never touched. No certificate to install.
            </p>

            <div className="mx-auto mt-5 max-w-2xl rounded-xl border-2 border-amber-300 bg-amber-50 p-4 text-left">
              <p className="text-sm font-semibold text-amber-900">
                Beta — research prototype. Not meant to be used live.
              </p>
              <p className="mt-1 text-xs leading-relaxed text-amber-900">
                Bouclier is published for evaluation, security research, and personal
                experimentation. It is <strong>not a commercial product</strong>, is{" "}
                <strong>not supported</strong>, and is{" "}
                <strong>
                  not meant for production, regulated workloads, or any environment where a failure
                  could cause harm
                </strong>
                . Detection is best-effort and evadable by a determined attacker — it raises cost,
                it is not a guarantee. See the{" "}
                <Link href="/terms" className="underline">
                  Terms
                </Link>{" "}
                before installing.
              </p>
            </div>

            <div className="mt-10 flex items-center justify-center gap-4">
              <a
                href={DOWNLOAD_URL}
                className="bg-bouclier shadow-bouclier/25 hover:bg-bouclier-dark hover:shadow-bouclier/30 inline-flex items-center gap-2 rounded-xl px-6 py-3.5 text-[15px] font-semibold text-white shadow-lg transition-all hover:shadow-xl"
              >
                <DownloadIcon />
                Download for macOS
              </a>
              <a
                href="#playground"
                className="border-border text-text hover:border-bouclier/30 inline-flex items-center gap-2 rounded-xl border bg-white px-6 py-3.5 text-[15px] font-semibold shadow-sm transition-all hover:shadow-md"
              >
                Try to sneak one past it
                <ArrowDown />
              </a>
            </div>

            <p className="text-text-secondary mt-5 text-sm">
              <span className="text-text font-semibold">Local-only.</span> {PATTERN_COUNT} detection
              patterns and an on-device ML classifier run on your Mac. No cloud scanning, no
              telemetry, no accounts.
            </p>
          </div>
        </div>
      </section>

      {/* ── Live playground ──────────────────────── */}
      <Playground />

      {/* ── How it works: provenance ─────────────── */}
      <section id="how" className="border-border border-t bg-white py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>How it works</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              It knows which bytes you wrote.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Every guardrail that scans &quot;the prompt&quot; eventually blocks its own user — the
              security engineer pasting an advisory, the developer testing a jailbreak. Bouclier
              splits the request by origin before it scores anything, so the action it takes depends
              on <em>who</em> said it, not just what was said.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-2 mt-12 grid gap-6 md:grid-cols-2">
            <div className="rounded-2xl border-2 border-red-200 bg-red-50/40 p-6">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                <h3 className="text-base font-semibold text-red-900">
                  Untrusted — flagged, or refused
                </h3>
              </div>
              <p className="text-text-secondary mt-3 text-sm leading-relaxed">
                <code className="rounded bg-white px-1 py-0.5 text-xs">tool_result</code> blocks,{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">role: &quot;tool&quot;</code>{" "}
                messages,{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">function_call_output</code>{" "}
                items, and retrieved content —{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">document</code> /{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">search_result</code> blocks
                and anything wrapped in the{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">&lt;document&gt;</code> RAG
                convention, even inside a user turn. Content your agent pulled from{" "}
                <em>outside your workspace</em> — the web, a search, an external tool. Nobody in the
                session wrote it, so an instruction in there is an attack by definition. By default
                it&apos;s logged and forwarded (monitor mode); turn on blocking and the request is
                refused with a 422 naming the pattern and the JSON path.
              </p>
            </div>
            <div className="border-border rounded-2xl border-2 bg-white p-6">
              <div className="flex items-center gap-2">
                <span className="bg-accent-green h-2 w-2 rounded-full" />
                <h3 className="text-base font-semibold">Yours — never blocked</h3>
              </div>
              <p className="text-text-secondary mt-3 text-sm leading-relaxed">
                Your prompt and system prompt — you are the principal, allowed to discuss attacks
                with your own model —{" "}
                <strong>and the files your agent reads from your own project</strong>: your docs,
                your <code className="rounded bg-white px-1 py-0.5 text-xs">CLAUDE.md</code>, your
                research notes. A file read from a path you control is trusted like your own words:
                scanned so the activity log stays useful, never blocked. Only content from outside
                your workspace can be refused — and the fetch-then-read dodge is still caught,
                because the fetch itself is inspected. Teams that want to police everything can turn
                on the stricter posture by MDM policy.
              </p>
            </div>
          </div>

          <div className="reveal border-border mt-8 rounded-2xl border bg-white p-6">
            <h3 className="text-lg font-semibold">What it does not claim</h3>
            <p className="text-text-secondary mt-2 text-sm leading-relaxed">
              Prompt injection is not solved, and a pattern engine is not a solution to it. The
              defences that actually hold are structural — constraining what a hijacked agent can
              reach, keeping untrusted input away from privileged actions. Bouclier is defence in
              depth on the untrusted leg: it raises the cost of the easy attacks and shows you when
              one arrives. Treat it the way you treat a WAF, not the way you treat a proof.
            </p>
          </div>

          <div className="reveal mt-6 rounded-2xl border-2 border-amber-200 bg-amber-50/50 p-6">
            <h3 className="text-lg font-semibold text-amber-900">What it does not stop</h3>
            <ul className="text-text-secondary mt-3 space-y-2 text-sm leading-relaxed">
              <li>
                <strong>An adaptive attacker.</strong> The detector matches known patterns; someone
                deliberately shaping a payload to slip past it will succeed. Public red-team results
                bypass every pattern-layer defence eventually.
              </li>
              <li>
                <strong>A process that doesn&apos;t route through the gateway.</strong> Protection
                is opt-in per process via{" "}
                <code className="rounded bg-white px-1 py-0.5">ANTHROPIC_BASE_URL</code> /{" "}
                <code className="rounded bg-white px-1 py-0.5">OPENAI_BASE_URL</code>. Anything that
                ignores those env vars (a tool with a hard-coded base URL, an already-running shell,
                an app with its own backend) talks to the provider directly.
              </li>
              <li>
                <strong>Injection the model reads by another path.</strong> Content in your own
                prompt, system prompt, or a file you read from your own project is treated as yours
                and forwarded unchanged; very large tool results are size-capped; today only
                Anthropic and OpenAI traffic is routed.
              </li>
              <li>
                <strong>Damage from an action that already ran.</strong> Bouclier inspects the
                request going out, not the model&apos;s tool calls coming back. Response-side action
                gating is on the roadmap, not shipped.
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* ── How we measure ───────────────────────── */}
      <section id="benchmarks" className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>How we measure</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Real numbers, on data we didn&apos;t write.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              We run the <em>shipped</em> pipeline — the {PATTERN_COUNT} patterns, the
              false-positive dampeners, and the on-device Prompt Guard 2 classifier — against
              third-party corpora, and publish the harness so you can reproduce it. Each test string
              is scored as untrusted tool output, exactly as the gateway would.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-2 mt-12 grid gap-6 md:grid-cols-2">
            <div className="border-border rounded-2xl border bg-white p-6">
              <div className="text-bouclier text-3xl font-bold tabular-nums">~1%</div>
              <h3 className="mt-1 text-base font-semibold">False positives on benign content</h3>
              <p className="text-text-secondary mt-2 text-sm leading-relaxed">
                Across 512 external benign prompts — including{" "}
                <a
                  href="https://github.com/leolee99/NotInject"
                  className="text-bouclier underline underline-offset-2"
                >
                  NotInject
                </a>
                , a set built to trip guardrails with security vocabulary — the shipped build
                blocked 0.6% (1.8% on NotInject alone). This is the number that matters for staying
                out of your way, and it&apos;s the hard one to game.
              </p>
            </div>
            <div className="border-border rounded-2xl border bg-white p-6">
              <div className="text-bouclier text-3xl font-bold tabular-nums">~99%</div>
              <h3 className="mt-1 text-base font-semibold">
                Instruction-override injections caught
              </h3>
              <p className="text-text-secondary mt-2 text-sm leading-relaxed">
                On 777 payloads from a public instruction-override corpus (Lakera&apos;s{" "}
                <code className="rounded bg-zinc-100 px-1 py-0.5 text-xs">gandalf</code> set). This
                is detection on a <em>static</em> corpus of one attack class — read it as coverage
                of known families, not a guarantee.
              </p>
            </div>
          </div>

          <div className="reveal mt-6 rounded-2xl border-2 border-amber-200 bg-amber-50/50 p-6">
            <h3 className="text-lg font-semibold text-amber-900">What these numbers are not</h3>
            <p className="text-text-secondary mt-2 text-sm leading-relaxed">
              These are <strong>static-corpus</strong> results. They say nothing about an attacker
              optimizing against the detector — every detector of this kind, ours included, is
              bypassed at high rates under adaptive attack. A clean pass is not evidence of safety.
              The default install runs in monitor mode and blocks nothing until you turn enforcement
              on. Measured on v{APP_VERSION} (10 Aug 2026); numbers move with each release.
            </p>
          </div>

          <div className="reveal mt-6">
            <a
              href="https://github.com/SuperstellarLLC/bouclier-ai/tree/main/apps/desktop/benchmark"
              className="border-border text-text hover:border-bouclier/30 inline-flex items-center gap-2 rounded-xl border bg-white px-5 py-3 text-sm font-semibold shadow-sm transition-all hover:shadow-md"
            >
              Reproduce it — the harness + corpora
              <span aria-hidden>→</span>
            </a>
          </div>
        </div>
      </section>

      {/* ── Built for agents (MCP + CLI) ──────────── */}
      <section id="agents" className="border-border border-t bg-white py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Built for agents</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Drive it from Claude Code — or any agent.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Bouclier ships an MCP server and a{" "}
              <code className="rounded bg-zinc-100 px-1 py-0.5 text-xs">bouclier</code> CLI that
              share one core. An agent can orient itself — is protection on, how much has it
              inspected — before it acts. What it <em>can&apos;t</em> do is the point: the CLI is
              read-only. There is no agent path to disable protection. The tool can&apos;t switch
              off the thing guarding it.
            </p>
          </div>

          <div className="reveal border-border mt-10 overflow-hidden rounded-2xl border bg-white">
            <div className="border-border bg-surface text-text-secondary border-b px-5 py-2.5 text-xs font-medium">
              the agent&apos;s view
            </div>
            <pre className="overflow-x-auto p-5 text-[13px] leading-relaxed">
              <code className="text-text">
                <span className="text-text-secondary">{"# orient before acting\n"}</span>
                {"bouclier status\n"}
                <span className="text-text-secondary">
                  {"→ protection ON (standard mode) · 128 inspected, 0 blocked\n\n"}
                </span>
                <span className="text-text-secondary">{"# there is no disable command\n"}</span>
                {"bouclier --help\n"}
                <span className="text-text-secondary">
                  {"→ status · install · --version  (read-only, by design)"}
                </span>
              </code>
            </pre>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-8 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="🟢"
              title="Read, freely"
              description="bouclier status returns protection state, mode, and activity counts as JSON. An agent can check it's protected before it runs — no approval needed to read."
            />
            <FlowCard
              step="🔌"
              title="One MCP server"
              description="Register the injection MCP with Claude Code once (bouclier install prints the command). Same read-only core as the CLI."
            />
            <FlowCard
              step="🔴"
              title="Never the agent"
              description="Disable protection or uninstall — neither has an agent path, only a human one in the app. The tool can't weaken its own guard."
            />
          </div>
        </div>
      </section>

      {/* ── No certificate / what reaches the model ─ */}
      <section id="trust" className="border-border border-t bg-white py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>No certificate</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              What reaches the model — and what doesn&apos;t.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Bouclier points your AI tools at a local gateway by setting a base URL — no root
              certificate, nothing installed in your trust store, no system-wide interception. The
              gateway never rewrites a request: it forwards it byte-for-byte, or refuses it
              outright. There is no in-between.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-12 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Prompts"
              description="Forwarded byte-for-byte. Bouclier has no rewrite path at all — a request is delivered unmodified or refused. No blind redactor touching your fields, nothing spliced into your prompt."
            />
            <FlowCard
              step="02"
              title="Headers"
              description="Authorization, x-api-key, trace IDs, analytics — every header reaches the upstream unmodified, so your tools keep working. Pinned by an end-to-end test so a future change can't drift."
            />
            <FlowCard
              step="03"
              title="Loopback only"
              description="The gateway binds 127.0.0.1 and nothing else — there's no system-wide traffic redirection. Only processes that explicitly point at it (ANTHROPIC_BASE_URL / OPENAI_BASE_URL) are ever in scope."
            />
          </div>

          <div className="reveal border-border mt-12 rounded-2xl border bg-white p-6">
            <p className="text-text-secondary text-sm">
              Bouclier installs nothing in your trust store. The byte-identical guarantee — a
              request is forwarded unchanged or refused, never rewritten — is pinned by an
              end-to-end test in CI on every release.
            </p>
          </div>
        </div>
      </section>

      {/* ── Enterprise ───────────────────────────── */}
      <section className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Enterprise</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Ready for your security team.
            </h2>
          </div>

          <div className="reveal-stagger reveal-stagger-2 mt-12 grid gap-6 md:grid-cols-2">
            <FeatureCard
              title="MDM managed"
              description="Deploy and configure via Jamf, Kandji, or Mosyle. Control the gateway port, additional AI domains, and feature flags — including enforcement mode — across your fleet."
            />
            <FeatureCard
              title="Fleet-wide enforcement"
              description="Ship monitor mode to learn your baseline, then flip blocking on by policy when you're ready. A single MDM flag turns the whole fleet from detect-and-log to refuse."
            />
            <FeatureCard
              title="Audit trail"
              description="Every inspected request and every refusal is logged locally and can be forwarded to your SIEM. Export a privacy-scrubbed diagnostics bundle for incident response."
            />
            <FeatureCard
              title="Tamper-resistant"
              description="An agent can use Bouclier but never weaken it — disabling protection has no agent path, only a human one in the app. The tool can't switch off its own guard."
            />
          </div>
        </div>
      </section>

      {/* ── Privacy ──────────────────────────────── */}
      <section id="privacy" className="border-border border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Privacy</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Nothing leaves your Mac.</h2>
          </div>

          <div className="reveal mt-12 grid gap-y-5">
            {[
              `Detection runs entirely on your Mac — ${PATTERN_COUNT} patterns and the on-device ML classifier. Your traffic never leaves the machine to be inspected.`,
              "No cloud LLM, no analytics, no telemetry in the app.",
              "Scan logs never contain your prompts, responses, or API keys — only metadata.",
              "Bouclier installs no certificate — the gateway is a plaintext-loopback relay, not a TLS-terminating proxy.",
            ].map((text) => (
              <div key={text} className="flex gap-3">
                <div className="bg-accent-green mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" />
                <p className="text-text-secondary">{text}</p>
              </div>
            ))}
            <div className="flex gap-3">
              <div className="bg-accent-green mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" />
              <p className="text-text-secondary">
                Published{" "}
                <Link href="/privacy" className="text-bouclier underline underline-offset-2">
                  threat model and privacy policy
                </Link>{" "}
                covering every trust boundary.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA ──────────────────────────────────── */}
      <section className="border-border bg-bouclier-dark border-t py-24">
        <div className="reveal-scale mx-auto max-w-5xl px-6 text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white">
            Put a firewall between your agent and the web.
          </h2>
          <p className="mx-auto mt-4 max-w-lg text-white/70">
            Download the DMG, drag to Applications, click Enable. Every tool result your agent reads
            is inspected for injection from that moment — on your Mac, nothing installed.
          </p>
          <a
            href={DOWNLOAD_URL}
            className="text-bouclier-dark mt-8 inline-flex items-center gap-2 rounded-xl bg-white px-8 py-4 text-[15px] font-semibold shadow-lg transition-all hover:shadow-xl"
          >
            <DownloadIcon />
            Download for macOS
          </a>
          <p className="mt-4 text-sm text-white/50">
            macOS 15+ &middot; Apple Silicon &amp; Intel &middot; v{APP_VERSION}
          </p>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────── */}
      <footer className="border-border border-t py-12">
        <div className="mx-auto max-w-5xl px-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Image
                src="/images/logo-64.png"
                alt="Bouclier.ai"
                width={20}
                height={20}
                className="rounded-[4px]"
              />
              <span className="text-text text-sm font-semibold">Bouclier.ai</span>
              <span className="rounded-md border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-amber-800">
                Beta
              </span>
            </div>
            <div className="text-text-secondary flex gap-6 text-sm">
              <Link href="/privacy" className="hover:text-text transition-colors">
                Privacy
              </Link>
              <Link href="/terms" className="hover:text-text transition-colors">
                Terms
              </Link>
            </div>
          </div>
          <p className="text-text-secondary mt-4 text-xs">
            Experimental, pre-1.0 software. Detection is best-effort; false positives and false
            negatives will occur. Not intended for production or regulated workloads — see{" "}
            <Link href="/terms" className="hover:text-text underline">
              Terms
            </Link>
            .
          </p>
        </div>
      </footer>
    </main>
  );
}

/* ── Components ──────────────────────────────────── */

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-bouclier text-xs font-semibold uppercase tracking-widest">
      {children}
    </span>
  );
}

function FlowCard({
  step,
  title,
  description,
}: {
  step: string;
  title: string;
  description: string;
}) {
  return (
    <div className="border-border rounded-2xl border bg-white p-6 shadow-sm">
      <span className="text-bouclier text-xs font-bold">{step}</span>
      <h3 className="mt-2 text-lg font-semibold">{title}</h3>
      <p className="text-text-secondary mt-2 text-sm leading-relaxed">{description}</p>
    </div>
  );
}

function FeatureCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="border-border rounded-2xl border bg-white p-6 shadow-sm">
      <h3 className="text-lg font-semibold">{title}</h3>
      <p className="text-text-secondary mt-2 text-sm leading-relaxed">{description}</p>
    </div>
  );
}

/* ── Icons ───────────────────────────────────────── */

function DownloadIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
    >
      <path d="M8 2v8m0 0l-3-3m3 3l3-3M3 12h10" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ArrowDown() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 14 14"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
    >
      <path d="M7 2v10m0 0l-3.5-3.5M7 12l3.5-3.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
