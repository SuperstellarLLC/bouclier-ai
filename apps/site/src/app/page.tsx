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
              href="#playground"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Try it
            </a>
            <a
              href="#trust"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Trust
            </a>
            <a
              href="#attachments"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Attachments
            </a>
            <a
              href="#how"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              How it works
            </a>
            <a
              href="#coverage"
              className="text-text-secondary hover:text-text text-sm transition-colors"
            >
              Coverage
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
              v{APP_VERSION} — {PATTERN_COUNT} patterns across {CATEGORY_COUNT} categories
            </div>

            <h1 className="text-text mx-auto max-w-3xl text-5xl font-bold leading-[1.1] tracking-tight sm:text-6xl">
              Stop prompt injections.
              <br />
              <span className="text-bouclier">Inspect what you upload to LLMs.</span>
            </h1>

            <p className="text-text-secondary mx-auto mt-6 max-w-2xl text-lg leading-relaxed">
              Bouclier.ai sits between your apps and AI providers. Every outbound request is scanned
              for prompt-injection attacks. Images, PDFs and short audio clips are inspected
              on-device — if they contain PII, the attachment is replaced with a plain-English
              description before it reaches the model. Your text prompts pass through byte-for-byte;
              auth headers and API keys are never touched. All inspection runs locally on your Mac.
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
                  not meant for production, regulated workloads, or any environment where a
                  detection failure could cause harm
                </strong>
                . Detection is best-effort; false positives and false negatives will occur. See the{" "}
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
                href="#how"
                className="border-border text-text hover:border-bouclier/30 inline-flex items-center gap-2 rounded-xl border bg-white px-6 py-3.5 text-[15px] font-semibold shadow-sm transition-all hover:shadow-md"
              >
                How it works
                <ArrowDown />
              </a>
            </div>

            <p className="text-text-secondary mt-5 text-sm">
              <span className="text-text font-semibold">Built with Llama.</span> Uses Meta Llama
              Prompt Guard 2 for on-device prompt attack detection.
            </p>
          </div>
        </div>
      </section>

      {/* ── Live playground ──────────────────────── */}
      <Playground />

      {/* ── Trust / what we don't touch ───────────── */}
      <section id="trust" className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>What we don&apos;t touch</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Your prompts and headers reach the model unchanged.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              A proxy that rewrites prompts is a proxy you can&apos;t trust. Bouclier sits in the
              middle of every AI request but it isn&apos;t a rewriter — prompt bodies traverse the
              proxy byte-for-byte and auth headers are forwarded untouched. The only thing Bouclier
              ever modifies on the way out is an attachment the on-device scanner flagged as
              containing PII, and even then we substitute a short text description, not a
              placeholder token that could trip the provider&apos;s abuse detection.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-12 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Prompts"
              description="Forwarded byte-for-byte. No tokenisation, no placeholder substitution, no JSON-blind rewriter that could touch user-identifier or analytics fields. The model receives your prompt exactly as your app sent it."
            />
            <FlowCard
              step="02"
              title="Headers"
              description="Authorization, x-api-key, X-Trace-ID, custom analytics, User-Agent — every header reaches the upstream unmodified. Pinned by an end-to-end test so a future change can't drift."
            />
            <FlowCard
              step="03"
              title="Attachments"
              description="The one thing Bouclier rewrites. Images, PDFs, audio that contain PII are replaced with a plain-English description — never with a token shape that could look adversarial to the model."
            />
          </div>

          <div className="reveal border-border mt-12 rounded-2xl border bg-white p-6">
            <p className="text-text-secondary text-sm">
              The byte-identical guarantee is pinned by{" "}
              <code className="text-text rounded bg-zinc-100 px-1.5 py-0.5 text-xs font-medium">
                E2EProxyTests
              </code>{" "}
              in CI — every release proves that a real CONNECT + TLS request through the proxy
              reaches the upstream with body, auth headers, API keys and trace IDs all intact. Read
              the{" "}
              <Link href="/terms" className="text-bouclier hover:underline">
                Terms
              </Link>{" "}
              for the limits of best-effort attachment detection.
            </p>
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
              images, PDFs and audio clips on the way out, scans them with Apple&apos;s on-device
              Vision, PDFKit and Speech frameworks, and replaces flagged attachments with a short
              text description so the model still gets the gist without the leak.
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
              Settings → Privacy. Multipart file uploads to the OpenAI Files API and Anthropic
              messages with PDF / image / audio blocks are all supported. Detection runs entirely on
              your Mac — no cloud OCR, no cloud transcription, no telemetry.
            </p>
          </div>
        </div>
      </section>

      {/* ── How it works ─────────────────────────── */}
      <section id="how" className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>How it works</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Intercept. Scan. Protect.</h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              A System Extension routes AI API traffic through a local proxy on your Mac. Every
              request and response is inspected before reaching the provider — no code changes, no
              SDK, no cloud dependency.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-3 mt-16 grid gap-6 md:grid-cols-3">
            <FlowCard
              step="01"
              title="Intercept"
              description="Traffic to 10+ AI providers is automatically routed through Bouclier.ai. Works with any app — ChatGPT, Cursor, Claude, API calls. No configuration needed."
            />
            <FlowCard
              step="02"
              title="Scan"
              description={`${PATTERN_COUNT} detection rules across ${CATEGORY_COUNT} attack categories. Requests, query strings, and streaming responses are all inspected in real time.`}
            />
            <FlowCard
              step="03"
              title="Protect"
              description="Threats are neutralized inline — injections are redacted before reaching the model. Streaming attacks are terminated cleanly. Safe traffic passes through untouched."
            />
          </div>

          {/* Flow diagram */}
          <div className="reveal border-border mt-16 rounded-2xl border bg-white p-8">
            <div className="flex flex-col items-center gap-3 sm:flex-row sm:gap-0">
              <FlowNode label="Your apps" sublabel="Any AI-powered tool on your Mac" />
              <FlowArrow />
              <FlowNode label="Bouclier.ai" sublabel="Local inspection" accent />
              <FlowArrow />
              <FlowNode label="AI providers" sublabel="OpenAI, Anthropic, Gemini, Mistral" />
            </div>
            <div className="text-text-secondary mt-6 flex justify-center gap-8 text-xs">
              <span className="flex items-center gap-1.5">
                <span className="bg-accent-green h-2 w-2 rounded-full" />
                Requests scanned
              </span>
              <span className="flex items-center gap-1.5">
                <span className="bg-bouclier h-2 w-2 rounded-full" />
                Streaming responses inspected
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Benchmark ────────────────────────────── */}
      <section className="border-border border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Results</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">Measured, not marketed.</h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Every release is tested against {BENCHMARK_ATTACKS} real-world attack samples and{" "}
              {BENCHMARK_BENIGN} benign inputs. Detection quality is enforced in CI — regressions
              block the release.
            </p>
          </div>

          <div className="reveal-stagger reveal-stagger-4 mt-12 grid gap-4 sm:grid-cols-4">
            <MetricCard value={BENCHMARK_TPR} label="Attacks caught" />
            <MetricCard value={BENCHMARK_FPR} label="False positive rate" />
            <MetricCard value={String(PATTERN_COUNT)} label="Detection rules" />
            <MetricCard value={String(CATEGORY_COUNT)} label="Attack categories" />
          </div>
        </div>
      </section>

      {/* ── Coverage ─────────────────────────────── */}
      <section id="coverage" className="border-border bg-surface border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Coverage</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              {CATEGORY_COUNT} attack categories.
            </h2>
            <p className="text-text-secondary mt-4 max-w-2xl">
              Sourced from OWASP LLM Top 10, MITRE ATLAS, HackAPrompt, and red-team research from
              Anthropic, Microsoft, and leading AI security labs.
            </p>
          </div>

          <div className="text-text-secondary mt-8 flex flex-wrap gap-x-6 gap-y-1 text-xs">
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

      {/* ── What it stops ────────────────────────── */}
      <section className="border-border border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>In action</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">What it stops.</h2>
          </div>

          <div className="reveal-stagger reveal-stagger-2 mt-12 grid gap-6 md:grid-cols-2">
            <ThreatCard
              label="BLOCKED"
              category="Role Hijack"
              severity="critical"
              description="Attempted to override the AI&rsquo;s instructions and extract its system prompt."
            />
            <ThreatCard
              label="BLOCKED"
              category="Multilingual Attack"
              severity="high"
              description="Injection disguised in French to bypass English-language detection."
            />
            <ThreatCard
              label="BLOCKED"
              category="Alignment Bypass"
              severity="critical"
              description="Known jailbreak technique (Skeleton Key) attempting to disable safety guardrails."
            />
            <ThreatCard
              label="BLOCKED"
              category="Tool Poisoning"
              severity="critical"
              description="Malicious instructions hidden in an MCP tool description, targeting SSH keys."
            />
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
              description="Deploy and configure via Jamf, Kandji, or Mosyle. Control intercepted domains, enforcement policy, and feature flags across your fleet."
            />
            <FeatureCard
              title="Audit trail"
              description="Every scan event is logged locally and can be forwarded to your SIEM. Export a privacy-scrubbed diagnostics bundle for incident response."
            />
            <FeatureCard
              title="Hardened by default"
              description="Built with defense-in-depth: request size limits, strict input validation, and a published threat model covering every trust boundary."
            />
            <FeatureCard
              title="Streaming protection"
              description="AI responses are inspected in real time as they stream. If a threat is detected mid-response, the stream is terminated cleanly."
            />
          </div>
        </div>
      </section>

      {/* ── Privacy ──────────────────────────────── */}
      <section className="border-border border-t py-24">
        <div className="mx-auto max-w-5xl px-6">
          <div className="reveal">
            <SectionLabel>Privacy</SectionLabel>
            <h2 className="mt-3 text-3xl font-bold tracking-tight">
              Your prompts never leave your Mac.
            </h2>
          </div>

          <div className="reveal mt-12 grid gap-y-5">
            {[
              "All detection runs locally. No cloud LLM, no analytics, no telemetry in the app.",
              "The local CA key is stored encrypted in your Keychain, unique to your device, and removable anytime.",
              "Scan logs never contain your prompts, responses, or API keys — only detection metadata.",
              "Local storage with automatic rotation. You own your data.",
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
            Install once. Protect everything.
          </h2>
          <p className="mx-auto mt-4 max-w-lg text-white/70">
            Download the DMG, drag to Applications, click Enable. Every AI request is protected from
            that moment.
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

function FlowNode({
  label,
  sublabel,
  accent,
}: {
  label: string;
  sublabel: string;
  accent?: boolean;
}) {
  return (
    <div
      className={`flex-1 rounded-xl border px-5 py-4 text-center ${accent ? "border-bouclier/30 bg-bouclier-light" : "border-border bg-white"}`}
    >
      <div className={`text-sm font-semibold ${accent ? "text-bouclier" : "text-text"}`}>
        {label}
      </div>
      <div className="text-text-secondary mt-0.5 text-xs">{sublabel}</div>
    </div>
  );
}

function FlowArrow() {
  return (
    <div className="text-border flex shrink-0 items-center px-2 sm:px-3">
      <svg
        width="24"
        height="12"
        viewBox="0 0 24 12"
        fill="none"
        className="text-text-secondary/40 rotate-90 sm:rotate-0"
      >
        <path d="M0 6h20m0 0l-4-4m4 4l-4 4" stroke="currentColor" strokeWidth="1.5" />
      </svg>
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

function ThreatCard({
  label,
  category,
  severity,
  description,
}: {
  label: string;
  category: string;
  severity: string;
  description: string;
}) {
  const severityColor =
    severity === "critical"
      ? "text-red-600 bg-red-50 border-red-200"
      : severity === "high"
        ? "text-orange-600 bg-orange-50 border-orange-200"
        : "text-amber-600 bg-amber-50 border-amber-200";

  return (
    <div className="border-border overflow-hidden rounded-2xl border bg-white">
      <div className="border-border bg-surface flex items-center justify-between border-b px-5 py-3">
        <div className="flex items-center gap-2">
          <span className="rounded bg-red-100 px-2 py-0.5 text-xs font-bold text-red-700">
            {label}
          </span>
          <span className="text-text-secondary text-xs">{category}</span>
        </div>
        <span
          className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${severityColor}`}
        >
          {severity}
        </span>
      </div>
      <div className="p-5">
        <p className="text-text-secondary text-sm leading-relaxed">{description}</p>
      </div>
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
