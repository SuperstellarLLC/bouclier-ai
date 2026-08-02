import Image from "next/image";
import Link from "next/link";
import { MobileNav } from "./mobile-nav";
import { Playground } from "./playground";
import { APP_VERSION, DOWNLOAD_URL } from "@/lib/constants";

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
              href="#secrets"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Secret keeper
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
              A web page should not be able
              <br />
              <span className="text-bouclier">to give your agent orders.</span>
            </h1>

            <p className="text-text-secondary mx-auto mt-6 max-w-2xl text-lg leading-relaxed">
              Bouclier.ai is a prompt-injection firewall that runs on your Mac, between your coding
              agent and the model provider. It reads every tool result on its way into the model — a
              fetched page, a README, an MCP response — and refuses the request when something in
              there is trying to reprogram your agent. Your own prompts are never touched. No
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
              <span className="text-text font-semibold">Local-only.</span> 161 detection patterns
              run on your Mac. No cloud scanning, no telemetry, no accounts.
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
                <h3 className="text-base font-semibold text-red-900">Untrusted — refused</h3>
              </div>
              <p className="text-text-secondary mt-3 text-sm leading-relaxed">
                <code className="rounded bg-white px-1 py-0.5 text-xs">tool_result</code> blocks,{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">role: &quot;tool&quot;</code>{" "}
                messages,{" "}
                <code className="rounded bg-white px-1 py-0.5 text-xs">function_call_output</code>{" "}
                items. Content your agent fetched on its own. Nobody in the session typed it, so an
                instruction in there is an attack by definition — the request is refused with a 403
                naming the pattern and the JSON path.
              </p>
            </div>
            <div className="border-border rounded-2xl border-2 bg-white p-6">
              <div className="flex items-center gap-2">
                <span className="bg-accent-green h-2 w-2 rounded-full" />
                <h3 className="text-base font-semibold">Yours — never blocked</h3>
              </div>
              <p className="text-text-secondary mt-3 text-sm leading-relaxed">
                Your prompt text and system prompt. Scanned so the activity log stays useful, then
                forwarded byte-for-byte no matter what it says. You are the principal; you are
                allowed to discuss attacks with your own model. Teams that want the stricter posture
                can turn it on by MDM policy.
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
        </div>
      </section>

      {/* ── Secret keeper (now secondary) ─────────── */}
      <section id="secrets" className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Also included — secret keeper</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Your agent uses the key. You keep the secret.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl text-sm">
              The other half of containing a hijacked agent: if an injection does get through, the
              credentials it tries to exfiltrate were never in the model&apos;s context to begin
              with. Opt-in, under Settings → Secrets.
            </p>
            <p className="text-text-secondary mt-4 max-w-2xl">
              When your agent needs a credential, Bouclier asks <em>you</em> — in a local dialog,
              not in the chat. You paste it (or let Bouclier generate one). It&apos;s stored in your
              Keychain and injected into the shells your agent spawns, so a command like{" "}
              <code className="text-text rounded bg-zinc-100 px-1.5 py-0.5 text-xs font-medium">
                curl -H &quot;Authorization: Bearer $STRIPE_KEY&quot;
              </code>{" "}
              just works — while the value never enters the model&apos;s context, the MCP channel,
              or any log.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-12 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Ask"
              description="The agent requests a secret by name. Bouclier opens a dialog where YOU paste or generate the value. The agent only ever learns the variable name — never the value."
            />
            <FlowCard
              step="02"
              title="Keep"
              description="The value lands in your macOS Keychain, scoped to Bouclier. On the way out, a managed secret is scrubbed to a placeholder so the model provider never sees it either, then restored in the response."
            />
            <FlowCard
              step="03"
              title="Use"
              description="It's injected into new shells as $ENV_VAR. Your agent uses it in real commands; the conversation and the model context stay clean."
            />
          </div>

          <div className="reveal border-border mt-12 rounded-2xl border bg-white p-6">
            <h3 className="text-lg font-semibold">Provision a whole project in one approval.</h3>
            <p className="text-text-secondary mt-2 text-sm leading-relaxed">
              Point your agent at a new repo&apos;s environment needs and approve them together —
              Bouclier shows one dialog, batches as many secrets as it takes, and tells the agent
              exactly which ones landed and which are still pending. Nothing is silently dropped.
              Pair it with the Vercel CLI (
              <code className="rounded bg-zinc-100 px-1 py-0.5 text-xs">
                echo &quot;$VAR&quot; | vercel env add
              </code>
              ) to set dozens of deployment variables without the agent — or the chat — ever seeing
              one.
            </p>
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
              share one core. An agent can orient itself, list and request secrets, and ask you to
              turn protection on. What it <em>can&apos;t</em> do is the point: it can never read a
              value, disable protection, or widen a secret&apos;s policy. The agent proposes; you
              approve; Bouclier enforces.
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
                  {"→ protection ON (standard mode) · 3 secrets usable\n\n"}
                </span>
                <span className="text-text-secondary">
                  {"# ask the human for what's missing\n"}
                </span>
                {'bouclier secrets request STRIPE_KEY DATABASE_URL --reason "deploy"\n'}
                <span className="text-text-secondary">
                  {"→ a dialog opens; you paste; the agent gets names, never values\n\n"}
                </span>
                <span className="text-text-secondary">{"# this is refused, by design\n"}</span>
                {"bouclier protection disable\n"}
                <span className="text-red-600">
                  {"→ not available to agents — do it in the app (exit 7)"}
                </span>
              </code>
            </pre>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-8 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="🟢"
              title="Read & use, freely"
              description="status, list secrets, request and activate them — no value is ever returned. The agent works on its own."
            />
            <FlowCard
              step="🟡"
              title="Propose, you approve"
              description="Turning protection on is a one-tap approval in Bouclier's own dialog. The agent suggests; the human decides."
            />
            <FlowCard
              step="🔴"
              title="Never the agent"
              description="Read a value, disable protection, uninstall — none of these have an agent path. The tool can't switch off the thing guarding it."
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
              By default Bouclier points your AI tools at a local gateway by setting a base URL — no
              root certificate, nothing installed in your trust store, no system-wide interception.
              Your prompts reach the provider byte-for-byte, with one deliberate exception: the
              managed secrets you asked Bouclier to keep out. Auth headers are forwarded untouched
              so your tools authenticate normally.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-12 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Prompts"
              description="Forwarded byte-for-byte — except a managed secret, which is swapped for a placeholder on the way out and restored in the response so the provider never sees it. No blind rewriter touching your other fields."
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
              Standard mode installs nothing. The byte-identical guarantee is pinned by an
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
              description="Deploy and configure via Jamf, Kandji, or Mosyle. Control the gateway port, additional AI domains for the secret keeper's host bookkeeping, and feature flags across your fleet."
            />
            <FeatureCard
              title="Audit trail"
              description="Every secret-keeper event is logged locally and can be forwarded to your SIEM. Export a privacy-scrubbed diagnostics bundle for incident response."
            />
            <FeatureCard
              title="Tamper-resistant"
              description="An agent can use Bouclier but never weaken it — disabling protection or reading a secret has no agent path, only a human one. The tool can't switch off its own guard."
            />
            <FeatureCard
              title="Straddle-safe restore"
              description="Secret placeholders are restored across streaming response chunks byte-for-byte, so your local tool calls still work even when the model streams the value back mid-token."
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
              "Secrets live in your macOS Keychain, scoped to Bouclier, and never reach the model, the MCP channel, or any log.",
              "No cloud LLM, no analytics, no telemetry in the app.",
              "Scan logs never contain your prompts, responses, secrets, or API keys — only metadata.",
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
            Give your agent the keys. Keep the secrets.
          </h2>
          <p className="mx-auto mt-4 max-w-lg text-white/70">
            Download the DMG, drag to Applications, click Enable. Your agent can start using secrets
            it never sees from that moment.
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
            Experimental, pre-1.0 software. Secret handling is best-effort; false positives and
            false negatives will occur. Not intended for production or regulated workloads — see{" "}
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
