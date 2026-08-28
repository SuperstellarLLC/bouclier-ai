import Image from "next/image";
import Link from "next/link";
import { MobileNav } from "./mobile-nav";
import { Playground } from "./playground";
import {
  APP_VERSION,
  DOWNLOAD_URL,
  ENFORCEMENT_STATUS_AVAILABLE,
  PATTERN_COUNT,
  STATUS_MCP_AVAILABLE,
} from "@/lib/constants";
import { BENCHMARK_PROVENANCE } from "@/lib/benchmark-provenance";

export default function Home() {
  const benchmark = BENCHMARK_PROVENANCE;

  return (
    <main className="min-h-screen">
      <a
        href="#main-content"
        className="bg-bouclier sr-only z-[100] rounded-md px-4 py-2 text-sm font-semibold text-white focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to main content
      </a>
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
      <section id="main-content" className="relative overflow-hidden" tabIndex={-1}>
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
              v{APP_VERSION} — detection runs entirely on your Mac
            </div>

            <h1 className="text-text mx-auto max-w-3xl text-4xl font-bold leading-[1.1] tracking-tight sm:text-6xl">
              Web pages should not
              <br />
              <span className="text-bouclier">give your agents instructions.</span>
            </h1>

            <p className="text-text-secondary mx-auto mt-6 max-w-2xl text-lg leading-relaxed">
              Bouclier.ai is a prompt-injection firewall that runs on your Mac, between your coding
              agent and the model provider. It reads the content your agent pulls in from the
              outside — a fetched web page, a search result, an MCP response — and flags signals
              that look like an attempt to reprogram it. It monitors by default; with blocking
              enabled, a request crossing the refusal threshold is stopped. Your own prompts — and
              only supported <code>Read</code> / <code>NotebookRead</code> results that Bouclier can
              positively link to a canonical, non-vendored path inside the active workspace — are
              forwarded unchanged and not blocked in normal mode. Missing or ambiguous attribution
              stays untrusted. That attribution is request-local; Bouclier does not track file taint
              or write history. A managed strict posture can choose to police trusted content. No
              certificate to install.
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

            <div className="mt-10 flex flex-col items-stretch justify-center gap-3 sm:flex-row sm:items-center sm:gap-4">
              <a
                href={DOWNLOAD_URL}
                className="bg-bouclier shadow-bouclier/25 hover:bg-bouclier-dark hover:shadow-bouclier/30 inline-flex items-center justify-center gap-2 rounded-xl px-6 py-3.5 text-[15px] font-semibold text-white shadow-lg transition-all hover:shadow-xl"
              >
                <DownloadIcon />
                Download for macOS
              </a>
              <a
                href="#playground"
                className="border-border text-text hover:border-bouclier/30 inline-flex items-center justify-center gap-2 rounded-xl border bg-white px-6 py-3.5 text-[15px] font-semibold shadow-sm transition-all hover:shadow-md"
              >
                Try to sneak one past it
                <ArrowDown />
              </a>
            </div>

            <p className="text-text-secondary mt-5 text-sm">
              <span className="text-text font-semibold">Detection is local-only.</span>{" "}
              {PATTERN_COUNT} patterns and an on-device ML classifier run on your Mac. No cloud
              scanning, app analytics, crash reporting, or accounts.
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
              It acts on origins the request can attribute.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Every guardrail that scans &quot;the prompt&quot; eventually blocks its own user — the
              security engineer pasting an advisory, the developer testing a jailbreak. Bouclier
              does not know who authored every byte. It classifies spans from request roles, tool
              linkage, and canonical paths before scoring, then chooses an action from that
              request-local attribution.
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
                convention, even inside a user turn. Content presented as external — or that the
                request cannot positively attribute to an eligible local read — is treated as
                untrusted input rather than authority. By default it&apos;s logged and forwarded
                (monitor mode); turn on blocking and a request over the refusal threshold is stopped
                with a 422 naming the pattern and JSON path.
              </p>
            </div>
            <div className="border-border rounded-2xl border-2 bg-white p-6">
              <div className="flex items-center gap-2">
                <span className="bg-accent-green h-2 w-2 rounded-full" />
                <h3 className="text-base font-semibold">
                  Attributed local read — forwarded in normal mode
                </h3>
              </div>
              <p className="text-text-secondary mt-3 text-sm leading-relaxed">
                Your prompt and system prompt are principal text. Separately, only supported local
                reads that Bouclier can positively attribute receive the authored classification.
                That means a <code className="rounded bg-white px-1 py-0.5 text-xs">Read</code> /{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">NotebookRead</code> result
                linked by <code className="rounded bg-white px-1 py-0.5 text-xs">tool_use_id</code>{" "}
                to a canonical, non-vendored path under a workspace root declared by the client. A
                missing or ambiguous link, a path outside that workspace, or a dependency, download,
                or temporary path stays untrusted. Positively attributed content is forwarded
                unchanged and never blocked in normal mode. When a routed request also contains
                supported untrusted tool output, principal spans may be scored and logged for
                context, but still cannot trigger a normal-mode detector refusal. Only supported
                untrusted content can trigger that kind of refusal in this posture. Authored is a
                request-local classification, not proof of file origin: Bouclier does not track file
                taint, writes, or content history across requests. If external content is silently
                saved into an otherwise eligible workspace path, a later linked read can look
                authored. A fetch is inspected at ingress only when its output itself appears as
                supported untrusted content in a routed model request. Separate malformed-request,
                unsupported-encoding, and transport limits can still reject a request. Teams that
                want to police every tool result can turn on the stricter posture by MDM policy.
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
                <strong>Injection in principal or positively attributed authored content.</strong>
                Your prompt and system prompt, plus supported local reads linked to a canonical,
                non-vendored path under the active workspace, are logged but not refused in normal
                mode. Anything Bouclier cannot attribute stays untrusted. Requests above the 8 MiB
                full-inspection limit receive only a bounded 24-window sample and a partial-coverage
                record; today only Anthropic and OpenAI traffic is routed.
              </li>
              <li>
                <strong>Action authorization.</strong> Bouclier does not approve, block, or undo a
                model&apos;s tool call. Response-action monitoring is not currently shipped: the
                response leg remains a raw, unchanged byte stream until a framing-aware observer can
                monitor it without missing or misparsing events.
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
              For this published measurement, we ran Bouclier v{benchmark.measuredRelease}&apos;s
              complete detector — {benchmark.pipeline.patternCount} patterns,{" "}
              {benchmark.pipeline.dampenerCount} false-positive dampeners, and the on-device{" "}
              {benchmark.pipeline.classifier} classifier{" "}
              {benchmark.pipeline.classifierActive ? "active" : "unavailable"} — against third-party
              corpora. Each string was scored as untrusted tool output, exactly as that
              release&apos;s gateway scored it.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-2 mt-12 grid gap-6 md:grid-cols-2">
            <div className="border-border min-w-0 rounded-2xl border bg-white p-6">
              <div className="text-bouclier text-3xl font-bold tabular-nums">
                {benchmark.benignCorpus.blockedPercent}%
              </div>
              <h3 className="mt-1 text-base font-semibold">False positives on benign content</h3>
              <p className="text-text-secondary mt-2 text-sm leading-relaxed">
                Across {benchmark.benignCorpus.total} external benign prompts — including{" "}
                <a
                  href="https://huggingface.co/datasets/leolee99/NotInject"
                  className="text-bouclier underline underline-offset-2"
                >
                  NotInject
                </a>
                {", "}a set built to trip guardrails with security vocabulary — v
                {benchmark.measuredRelease} would have refused{" "}
                {benchmark.benignCorpus.blockedPercent}% with blocking enabled (
                {benchmark.benignCorpus.notInjectBlockedPercent}% on NotInject alone). This is the
                number that matters for staying out of your way, and it&apos;s the hard one to game.
              </p>
            </div>
            <div className="border-border min-w-0 rounded-2xl border bg-white p-6">
              <div className="text-bouclier text-3xl font-bold tabular-nums">
                {benchmark.instructionOverrideCorpus.detectedPercent}%
              </div>
              <h3 className="mt-1 text-base font-semibold">
                Instruction-override injections detected
              </h3>
              <p className="text-text-secondary mt-2 text-sm leading-relaxed">
                Bouclier v{benchmark.measuredRelease} produced a block or flag for{" "}
                {benchmark.instructionOverrideCorpus.detectedPercent}% of{" "}
                {benchmark.instructionOverrideCorpus.total} payloads from a public
                instruction-override corpus,{" "}
                <code className="break-all rounded bg-zinc-100 px-1 py-0.5 text-xs">
                  {benchmark.instructionOverrideCorpus.name}
                </code>
                {". "}This is detection on a <em>static</em> corpus of one attack class — read it as
                coverage of known families, not a guarantee.
              </p>
            </div>
          </div>

          <div className="reveal mt-6 rounded-2xl border-2 border-amber-200 bg-amber-50/50 p-6">
            <h3 className="text-lg font-semibold text-amber-900">What these numbers are not</h3>
            <p
              className="text-text-secondary mt-2 text-sm leading-relaxed"
              data-testid="benchmark-provenance"
            >
              These are <strong>static-corpus</strong> results. They say nothing about an attacker
              optimizing against the detector — every detector of this kind, ours included, is
              bypassed at high rates under adaptive attack. A clean pass is not evidence of safety.
              The default install runs in monitor mode and blocks nothing until you turn enforcement
              on. Measured on{" "}
              <time dateTime={benchmark.measuredOnISO}>{benchmark.measuredOnLabel}</time> with
              Bouclier v{benchmark.measuredRelease} at the untrusted blocking threshold of{" "}
              {benchmark.pipeline.untrustedBlockThreshold}; this evidence stays pinned to that
              release. Newer versions are not represented until the harness is rerun and a new
              provenance record is published.
            </p>
          </div>

          <div className="reveal mt-6">
            <a
              href={benchmark.sourceUrl}
              className="border-border text-text hover:border-bouclier/30 inline-flex items-center gap-2 rounded-xl border bg-white px-5 py-3 text-sm font-semibold shadow-sm transition-all hover:shadow-md"
            >
              Reproduce the v{benchmark.measuredRelease} measurement — harness + corpora
              <span aria-hidden>→</span>
            </a>
          </div>
        </div>
      </section>

      {/* ── Built for agents (CLI, plus MCP in the next signed release) ── */}
      <section id="agents" className="border-border border-t bg-white py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Built for agents</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Drive it from Claude Code — or any agent.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Bouclier ships a read-only{" "}
              <code className="rounded bg-zinc-100 px-1 py-0.5 text-xs">bouclier</code> CLI. An
              agent can orient itself — is protection on, how much has it inspected — before it
              acts.{" "}
              {STATUS_MCP_AVAILABLE
                ? "This release also exposes the same status through a read-only MCP server. "
                : ""}
              These visibility interfaces expose no setting mutation and are not tamper resistance:
              a process running as the same macOS user can still bypass the configured route or stop
              the app.
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
                  {ENFORCEMENT_STATUS_AVAILABLE
                    ? `→ Bouclier ${APP_VERSION}: protection ON — monitoring (standard mode)\n  engine: ${PATTERN_COUNT} patterns, Prompt Guard 2 active\n  activity: 128 requests inspected, 0 monitor findings allowed, 0 requests blocked by the detector, 0 coverage refusals, 0 inspection skips\n\n`
                    : `→ Bouclier ${APP_VERSION}: protection ON (standard mode) · 128 inspected, 0 blocked\n\n`}
                </span>
                {ENFORCEMENT_STATUS_AVAILABLE ? (
                  <span className="text-text-secondary">
                    {"# if a human enables enforcement, status reports\n"}
                    {"→ protection ON — blocking (standard mode)\n\n"}
                  </span>
                ) : null}
                <span className="text-text-secondary">{"# there is no disable command\n"}</span>
                {"bouclier --help\n"}
                <span className="text-text-secondary">
                  {"→ status · install · --version  (read-only, by design)"}
                </span>
              </code>
            </pre>
          </div>

          <div
            className={`reveal-stagger reveal-stagger-3 mt-8 grid gap-6 ${STATUS_MCP_AVAILABLE ? "md:grid-cols-3" : "md:grid-cols-2"}`}
          >
            <FlowCard
              step="🟢"
              title="Read, freely"
              description={`bouclier status returns a human-readable protection state${ENFORCEMENT_STATUS_AVAILABLE ? ", enforcement mode, detector-tier health," : " and"} activity counts; add --json for machine output. An agent can check before it runs — no approval needed to read.`}
            />
            {STATUS_MCP_AVAILABLE ? (
              <FlowCard
                step="🔌"
                title="One MCP server"
                description="Register the read-only status MCP with Claude Code once (bouclier install prints the command). It exposes protection state, enforcement mode, detector-tier health, and activity counts — no mutation tools."
              />
            ) : null}
            <FlowCard
              step="🔴"
              title="Read-only surface"
              description={`${STATUS_MCP_AVAILABLE ? "The CLI and MCP have" : "The CLI has"} no disable or settings tools. Same-user process and routing controls remain outside this interface, so managed deployments need OS policy too.`}
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
              gateway never rewrites the model-visible body: those bytes are forwarded unchanged, or
              the request is refused outright. Normal proxy framing is still normalized.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-12 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Prompt body"
              description="Model-visible body bytes are forwarded unchanged or the request is refused. There is no blind redactor touching your fields and nothing is spliced into your prompt."
            />
            <FlowCard
              step="02"
              title="Headers"
              description="End-to-end headers such as Authorization, x-api-key, and trace IDs are preserved. Like a correct HTTP proxy, Bouclier rewrites Host and Content-Length and strips hop-by-hop and Proxy-Authorization headers."
            />
            <FlowCard
              step="03"
              title="Loopback only"
              description="The gateway binds 127.0.0.1 and nothing else — there's no system-wide traffic redirection. Only processes that explicitly point at it (ANTHROPIC_BASE_URL / OPENAI_BASE_URL) are ever in scope."
            />
          </div>

          <div className="reveal border-border mt-12 rounded-2xl border bg-white p-6">
            <p className="text-text-secondary text-sm">
              Bouclier installs nothing in your trust store. The body-byte guarantee — the
              model-visible body is forwarded unchanged or its request is refused, never rewritten —
              is pinned by an end-to-end test in CI on every release.
            </p>
          </div>
        </div>
      </section>

      {/* ── Enterprise ───────────────────────────── */}
      <section className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Managed evaluation</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Evaluate it with your security team.
            </h2>
          </div>

          <div className="reveal-stagger reveal-stagger-2 mt-12 grid gap-6 md:grid-cols-2">
            <FeatureCard
              title="MDM managed"
              description="Configure evaluation builds via Jamf, Kandji, or Mosyle. Control the gateway port, enforcement policy, in-app controls for disabling or configuration removal, and the SIEM destination across a test fleet. These preferences are not same-user tamper protection."
            />
            <FeatureCard
              title="Fleet-wide enforcement"
              description="On installs already enabled and explicitly routed through the gateway, start in monitor mode, then change findings from detect-and-log to refuse by policy. The enforcement flag does not activate or reroute a fresh install."
            />
            <FeatureCard
              title="Audit trail"
              description="Inspection activity stays in the local log; configured SIEM webhooks receive detection metadata, never prompt bodies. Export a privacy-scrubbed diagnostics bundle for incident response."
            />
            <FeatureCard
              title="Read-only agent access"
              description={`${STATUS_MCP_AVAILABLE ? "The bundled CLI and MCP expose" : "The bundled CLI exposes"} status only and contains no disable command. MDM can lock the app's controls; preventing a same-user process from killing or bypassing the app requires separate endpoint policy.`}
            />
          </div>
        </div>
      </section>

      {/* ── Privacy ──────────────────────────────── */}
      <section id="privacy" className="border-border border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Privacy</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Detection stays on your Mac.</h2>
          </div>

          <div className="reveal mt-12 grid gap-y-5">
            {[
              `Detection runs entirely on your Mac — ${PATTERN_COUNT} patterns and the on-device ML classifier. Your traffic never leaves the machine to be inspected.`,
              "No cloud LLM, app analytics, crash reporting, or passive telemetry to Bouclier.ai.",
              "Routine scan logs never contain your prompts, responses, or API keys — only metadata.",
              "Optional block-sample capture is off by default and stays in a local file. A false-positive report leaves your Mac only after you review its contents and confirm sending it.",
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
                documenting the gateway&apos;s trust boundaries and external data flows.
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
            Download the DMG, drag to Applications, click Enable. After setup, supported CLI
            processes started with Bouclier&apos;s gateway environment inspect routed tool results
            locally, in monitor mode by default.
          </p>
          <a
            href={DOWNLOAD_URL}
            className="text-bouclier-dark mt-8 inline-flex items-center gap-2 rounded-xl bg-white px-8 py-4 text-[15px] font-semibold shadow-lg transition-all hover:shadow-xl"
          >
            <DownloadIcon />
            Download for macOS
          </a>
          <p className="mt-4 text-sm text-white/70">
            macOS 15+ &middot; Apple silicon &middot; v{APP_VERSION}
          </p>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────── */}
      <footer className="border-border border-t py-12">
        <div className="mx-auto max-w-5xl px-6">
          <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
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
            Built with Llama. Meta Prompt Guard 2 runs locally in the macOS app. <br />
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
      <span aria-hidden="true" className="text-bouclier text-xs font-bold">
        {step}
      </span>
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
      aria-hidden="true"
      focusable="false"
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
      aria-hidden="true"
      focusable="false"
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
