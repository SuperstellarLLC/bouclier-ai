import Image from "next/image";
import Link from "next/link";
import { MobileNav } from "./mobile-nav";
import { Playground } from "./playground";
import {
  APP_VERSION,
  BENCHMARK_ATTACKS,
  BENCHMARK_BENIGN,
  BENCHMARK_FPR,
  BENCHMARK_TPR,
  CATEGORY_COUNT,
  DOWNLOAD_URL,
  PATTERN_COUNT,
} from "@/lib/constants";

const CATEGORIES = [
  { name: "Role Hijack", count: 6, color: "bg-red-500" },
  { name: "Instruction Override", count: 5, color: "bg-red-500" },
  { name: "Tool Poisoning", count: 12, color: "bg-red-500" },
  { name: "Credential Leak", count: 11, color: "bg-red-500" },
  { name: "Memory Manipulation", count: 9, color: "bg-red-500" },
  { name: "Function Hijack", count: 8, color: "bg-red-500" },
  { name: "Model-Specific", count: 14, color: "bg-red-500" },
  { name: "Alignment Bypass", count: 14, color: "bg-red-500" },
  { name: "Code Injection", count: 10, color: "bg-orange-500" },
  { name: "Sandbox Escape", count: 8, color: "bg-orange-500" },
  { name: "Data Exfiltration", count: 6, color: "bg-orange-500" },
  { name: "Indirect Injection", count: 7, color: "bg-orange-500" },
  { name: "Context Manipulation", count: 5, color: "bg-orange-500" },
  { name: "Chain-of-Thought", count: 7, color: "bg-amber-500" },
  { name: "Delimiter Attacks", count: 4, color: "bg-amber-500" },
  { name: "Encoding Bypass", count: 5, color: "bg-amber-500" },
  { name: "Multilingual", count: 15, color: "bg-amber-500" },
  { name: "Payload Splitting", count: 3, color: "bg-amber-500" },
  { name: "Obfuscation", count: 5, color: "bg-yellow-500" },
  { name: "Prompt Leaking", count: 4, color: "bg-yellow-500" },
  { name: "Recursive Injection", count: 3, color: "bg-yellow-500" },
] as const;

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
              href="#secrets"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Secret keeper
            </a>
            <a
              href="#agents"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              For agents
            </a>
            <a
              href="#firewall"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Firewall
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
              Your AI agent can use your secrets.
              <br />
              <span className="text-bouclier">It never sees them.</span>
            </h1>

            <p className="text-text-secondary mx-auto mt-6 max-w-2xl text-lg leading-relaxed">
              Bouclier.ai runs on your Mac, between your AI tools and the providers. When your
              coding agent — Claude Code, Cursor — needs an API key, it gets it through your shell,
              never into the model&apos;s context. It can provision a whole project&apos;s
              environment variables in a single approval. And it still blocks prompt-injection
              attacks and strips PII from what you upload. No certificate to install.
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
                . Secret handling and detection are best-effort; review what you store. See the{" "}
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
                href="#secrets"
                className="border-border text-text hover:border-bouclier/30 inline-flex items-center gap-2 rounded-xl border bg-white px-6 py-3.5 text-[15px] font-semibold shadow-sm transition-all hover:shadow-md"
              >
                How the secret keeper works
                <ArrowDown />
              </a>
            </div>

            <p className="text-text-secondary mt-5 text-sm">
              <span className="text-text font-semibold">Local-only.</span> Secrets live in your
              macOS Keychain. Prompt-injection detection uses Meta Llama Prompt Guard 2, on-device.
            </p>
          </div>
        </div>
      </section>

      {/* ── Secret keeper (the centerpiece) ───────── */}
      <section id="secrets" className="border-border border-t bg-white py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Secret keeper</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Your agent uses the key. You keep the secret.
            </h2>
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
      <section id="agents" className="border-border bg-surface border-t py-24">
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
              value, disable the firewall, or widen a secret&apos;s policy. The agent proposes; you
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
              description="Read a value, disable protection, install a certificate, uninstall — none of these have an agent path. The tool can't switch off the thing guarding it."
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
              title="Attachments"
              description="Images, PDFs and audio that the on-device scanner flags for PII are replaced with a short plain-English description — never a token shape that could look adversarial to the model."
            />
          </div>

          <div className="reveal border-border mt-12 rounded-2xl border bg-white p-6">
            <p className="text-text-secondary text-sm">
              Need full TLS inspection — deep prompt-injection scanning, or injecting a secret
              straight into a third-party API? That&apos;s an opt-in <strong>extreme mode</strong>{" "}
              behind a clear warning; it installs a local CA and routes more traffic through the
              proxy. Standard mode (the default) installs nothing. The byte-identical guarantee is
              pinned by{" "}
              <code className="text-text rounded bg-zinc-100 px-1.5 py-0.5 text-xs font-medium">
                E2EProxyTests
              </code>{" "}
              in CI on every release.
            </p>
          </div>
        </div>
      </section>

      {/* ── Prompt-injection firewall ─────────────── */}
      <section id="firewall" className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Prompt-injection firewall</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              And it still watches for attacks.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              The same proxy scans outbound requests, MCP tool results, and streaming responses for
              prompt-injection and jailbreak attempts — {PATTERN_COUNT} detection rules across{" "}
              {CATEGORY_COUNT} categories, plus an on-device Llama Prompt Guard 2 classifier. Safe
              traffic passes through untouched; threats are redacted or the stream is cut cleanly.
              Try a payload below.
            </p>
          </div>
        </div>

        {/* Live playground */}
        <div className="mt-12">
          <Playground />
        </div>

        {/* Benchmark */}
        <div className="mx-auto mt-16 max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Measured, not marketed</SectionLabel>
            <p className="text-text-secondary mt-3 max-w-2xl">
              Every release is tested against {BENCHMARK_ATTACKS} real-world attack samples and{" "}
              {BENCHMARK_BENIGN} benign inputs. Detection quality is enforced in CI — regressions
              block the release.
            </p>
          </div>
          <div className="reveal-stagger reveal-stagger-4 mt-8 grid gap-4 sm:grid-cols-4">
            <MetricCard value={BENCHMARK_TPR} label="Attacks caught" />
            <MetricCard value={BENCHMARK_FPR} label="False positive rate" />
            <MetricCard value={String(PATTERN_COUNT)} label="Detection rules" />
            <MetricCard value={String(CATEGORY_COUNT)} label="Attack categories" />
          </div>
        </div>

        {/* Coverage */}
        <div className="mx-auto mt-16 max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Coverage</SectionLabel>
            <p className="text-text-secondary mt-3 max-w-2xl">
              Sourced from OWASP LLM Top 10, MITRE ATLAS, HackAPrompt, and red-team research from
              Anthropic, Microsoft, and leading AI security labs.
            </p>
          </div>
          <div className="text-text-secondary mt-6 flex flex-wrap gap-x-6 gap-y-1 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-red-500" /> Critical
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-orange-500" /> High
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> Medium-High
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-yellow-500" /> Medium
            </span>
          </div>
          <div className="reveal-stagger reveal-stagger-3 mt-6 grid gap-2 sm:grid-cols-3">
            {CATEGORIES.map((cat) => (
              <div
                key={cat.name}
                className="border-border hover:border-bouclier/30 flex items-center justify-between rounded-lg border bg-white px-4 py-3 transition-colors"
              >
                <span className="text-sm font-medium">{cat.name}</span>
                <span
                  className={`inline-flex h-6 min-w-[28px] items-center justify-center rounded-full ${cat.color} px-2 text-xs font-bold text-white`}
                >
                  {cat.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Attachment PII inspection ─────────────── */}
      <section id="attachments" className="border-border border-t bg-white py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Attachment PII</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              PII hides in what you upload.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              A screenshot of an invoice, a scanned NDA, a 30-second voice memo — modern LLM clients
              accept all of it, and a regex pass over the JSON body sees none of it. Bouclier opens
              images, PDFs and audio on the way out, scans them with Apple&apos;s on-device Vision,
              PDFKit and Speech frameworks, and replaces flagged attachments with a short text
              description so the model still gets the gist without the leak.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-12 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Images"
              description="Vision OCR + face detection on every image in OpenAI / Anthropic / Gemini multimodal shapes. EXIF orientation honored, 2000 px downscale, 4-concurrency throttle."
            />
            <FlowCard
              step="02"
              title="PDFs"
              description="PDFKit text-layer extraction with Vision OCR fallback for scanned pages. Encrypted or oversized PDFs surface as unscannable and get stripped — never silently forwarded."
            />
            <FlowCard
              step="03"
              title="Audio"
              description="On-device Apple Speech transcription up to 60 seconds. No audio leaves your Mac. Unsupported formats get blocked rather than passed through."
            />
          </div>

          <div className="reveal border-border mt-12 rounded-2xl border bg-white p-6">
            <p className="text-text-secondary text-sm">
              Attachment inspection ships <strong>off by default</strong> and is opt-in from
              Settings → Privacy. Detection runs entirely on your Mac — no cloud OCR, no cloud
              transcription, no telemetry.
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
              description="Deploy and configure via Jamf, Kandji, or Mosyle. Control mode, intercepted domains, enforcement policy, and feature flags across your fleet."
            />
            <FeatureCard
              title="Audit trail"
              description="Every scan event is logged locally and can be forwarded to your SIEM. Export a privacy-scrubbed diagnostics bundle for incident response."
            />
            <FeatureCard
              title="Tamper-resistant"
              description="An agent can use Bouclier but never weaken it — disabling protection or reading a secret has no agent path, only a human one. The tool can't switch off its own guard."
            />
            <FeatureCard
              title="Streaming protection"
              description="AI responses are inspected in real time as they stream. If a threat is detected mid-response, the stream is terminated cleanly."
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
              "All detection runs locally. No cloud LLM, no analytics, no telemetry in the app.",
              "Scan logs never contain your prompts, responses, secrets, or API keys — only detection metadata.",
              "Standard mode installs no certificate. Extreme mode's local CA key is encrypted in your Keychain, unique to your device, and removable anytime.",
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
              <Link href="/blocked" className="hover:text-text transition-colors">
                Blocked
              </Link>
              <Link href="/privacy" className="hover:text-text transition-colors">
                Privacy
              </Link>
              <Link href="/terms" className="hover:text-text transition-colors">
                Terms
              </Link>
            </div>
          </div>
          <p className="text-text-secondary mt-4 text-xs">
            Built with Llama. Uses Meta Llama Prompt Guard 2 for on-device prompt attack detection.
          </p>
          <p className="text-text-secondary mt-1 text-xs">
            Experimental, pre-1.0 software. Secret handling and detection are best-effort; false
            positives and false negatives will occur. Not intended for production or regulated
            workloads — see{" "}
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

function MetricCard({ value, label }: { value: string; label: string }) {
  return (
    <div className="bg-surface border-border rounded-2xl border p-6 text-center">
      <div className="text-text text-3xl font-bold tracking-tight">{value}</div>
      <div className="text-text-secondary mt-1 text-sm">{label}</div>
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
