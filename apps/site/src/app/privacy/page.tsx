import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

import { APP_URL } from "@/lib/constants";

const DESCRIPTION =
  "How Bouclier.ai processes AI traffic locally, what the website records, and what an optional false-positive report contains.";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: DESCRIPTION,
  alternates: { canonical: `${APP_URL}/privacy` },
  openGraph: {
    title: "Bouclier.ai Privacy Policy",
    description: DESCRIPTION,
    url: `${APP_URL}/privacy`,
    type: "article",
  },
};

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-white">
      <nav className="border-border border-b" aria-label="Primary">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-6 py-4">
          <Link href="/" className="text-text flex items-center gap-2 text-sm font-semibold">
            <Image
              src="/images/logo-64.png"
              alt="Bouclier.ai"
              width={20}
              height={20}
              className="rounded-[4px]"
            />
            Bouclier.ai
            <span className="rounded-md border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-amber-800">
              Beta
            </span>
          </Link>
          <div className="text-text-secondary flex gap-6 text-sm">
            <Link href="/" className="hover:text-text transition-colors">
              Home
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-3xl font-bold tracking-tight">Privacy Notice</h1>
        <p className="text-text-secondary mt-2 text-sm">Last updated: 28 August 2026</p>

        {/* Loud prototype banner mirroring the Terms — privacy posture is also research-grade. */}
        <div className="mt-10 rounded-xl border-2 border-amber-300 bg-amber-50 p-6">
          <p className="font-semibold text-amber-900">
            Bouclier.ai is a research prototype. It is not a commercial product.
          </p>
          <p className="mt-2 text-sm text-amber-900">
            The Software and the Site are published for evaluation, security research, academic
            study, and personal experimentation only. The privacy posture described below reflects
            this status and does not constitute a commercial data-processing offering. See the{" "}
            <Link href="/terms" className="font-medium underline">
              Terms of Use
            </Link>{" "}
            for the full prototype framing.
          </p>
        </div>

        {/* Summary box */}
        <div className="border-accent-green/30 mt-6 rounded-xl border-2 bg-emerald-50 p-6">
          <p className="font-medium text-emerald-900">
            Detection runs on your device. Allowed AI requests and responses still travel to the
            provider you configured, but Bouclier does not automatically send their content to its
            own servers. The app has no user accounts, analytics, or crash reporting. It does check
            for updates; the Site records a timestamp, app version, and channel when a download is
            requested; and you can explicitly send a best-effort-redacted false-positive report
            after reviewing it. Hosting providers also receive ordinary HTTP transport metadata.
            Full scope is described below.
          </p>
        </div>

        <Section title="What Bouclier.ai does">
          Bouclier.ai runs a local gateway on your Mac. You point your AI agent&apos;s SDK at it (
          <code>ANTHROPIC_BASE_URL</code> / <code>OPENAI_BASE_URL</code>) instead of the provider
          directly; the gateway re-issues each request to the real provider over TLS and streams the
          response back. There is no system-wide traffic interception, no certificate authority, and
          no decryption of traffic the gateway wasn&apos;t explicitly pointed at. Model-visible body
          bytes and end-to-end headers such as Authorization are preserved. As an HTTP proxy, the
          gateway rewrites Host and Content-Length and strips hop-by-hop and Proxy-Authorization
          headers. It never rewrites the prompt body: that body is forwarded unchanged or, when a
          finding in untrusted content crosses the refusal threshold and blocking is enabled, the
          request is refused locally with a 422.
        </Section>

        <Section title="Providers reached">
          <p>The gateway routes requests to whichever provider the request targets. Built in:</p>
          <div className="border-border bg-surface mt-3 rounded-lg border px-4 py-3 font-mono text-sm">
            api.openai.com, api.anthropic.com
          </div>
          <p className="text-text-secondary mt-3 text-sm">
            The current gateway supports these two provider hosts. MDM can set the local gateway
            port, but does not add a live upstream provider route.
          </p>
        </Section>

        <Section title="Network connections">
          <ol className="list-decimal space-y-3 pl-5">
            <li>
              <strong>AI API forwarding</strong> — forwarding model-visible request bodies to their
              intended destination without rewriting those bytes. End-to-end headers are preserved;
              proxy routing and framing headers are normalized as described above. A body is
              forwarded unchanged or its request is refused locally.
            </li>
            <li>
              <strong>Update check</strong> — checking for software updates via appcast.xml hosted
              on bouclier.ai. Transmits app version, macOS version, CPU architecture, and preferred
              language. No prompt or report content; the hosting layer still receives ordinary HTTP
              transport metadata such as the transit IP and request time.
            </li>
            <li>
              <strong>SIEM webhook (MDM-managed only)</strong> — if and only if configured by an
              organization&apos;s IT administrator via MDM, detection event metadata (timestamp,
              event kind, host, match count, pattern names, severity, request-body size, and app
              version) is sent to that organization-controlled endpoint. Never enabled by default.
              Cannot be configured by the user. Prompt bodies are not included.
            </li>
          </ol>
        </Section>

        <Section title="Marketing site (bouclier.ai)">
          <p>
            When you click the &quot;Download&quot; button on bouclier.ai, the server records a
            single application-level event consisting of <strong>(a) the time of the click</strong>,{" "}
            <strong>(b) the requested app version</strong>, and{" "}
            <strong>(c) the channel string</strong> (e.g. &quot;site&quot;) that the link carries.
            That record contains no user identifier.
          </p>
          <p className="mt-3">The Bouclier-controlled download record does not include:</p>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            <li>your IP address;</li>
            <li>your user-agent string or device fingerprint;</li>
            <li>the referring page or any UTM parameter;</li>
            <li>your country or any geolocation derived from the request;</li>
            <li>any cookie, session token, or other identifier.</li>
          </ul>
          <p className="mt-3 text-sm">
            The event is recorded so we can measure beta downloads. Separately, Vercel receives the
            HTTP request needed to serve the Site and redirect the download and may log standard
            transport metadata; see &quot;Sub-processors&quot;. The Site does not load a product
            analytics service or set an analytics identifier. The recent-event list is capped at
            5,000 entries, so older event rows fall off as new downloads arrive. Anonymous lifetime,
            daily, version, and channel counters are retained for service operations until the
            download store is reset.
          </p>
        </Section>

        <Section title="Data stored locally">
          <p>Stored at ~/Library/Application Support/ai.bouclier.app/:</p>
          <ul className="mt-3 space-y-2">
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Scan logs</strong> — timestamp, source, target host, event kind, request
                size. No request body content. Auto-deleted after 30 days.
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Block samples (opt-in, off by default)</strong> — only when you enable
                &quot;Capture blocked content for tuning&quot;: the offending untrusted span
                excerpt, the per-signal breakdown, and the passage the classifier reacted to, stored
                in a local file (block-samples.jsonl). Never transmitted unless you explicitly tap
                &quot;Report false positive&quot; (see &quot;Data we share&quot;).
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Daily stats</strong> — date, requests inspected, requests blocked by the
                detector. Retained 365 days.
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Preferences</strong> — gateway port, notifications, launch-at-login. Via
                UserDefaults.
              </span>
            </li>
          </ul>
        </Section>

        <Section title="Data Bouclier receives">
          <p>
            The app has no user accounts, product analytics, crash reporting, or passive prompt
            telemetry. Bouclier servers do receive the update and Site requests described above; the
            download endpoint stores only the scoped event fields and anonymous counters described
            above.
          </p>
          <p className="mt-3">
            If you choose &quot;Report false positive&quot;, we receive and store that report for
            detector tuning. Our retention period is <strong>90 days</strong>: a report becomes
            eligible for deletion after that period and is pruned on the next valid report intake. A
            deployment that must delete expired rows while intake is idle must run the scheduled
            daily cleanup documented in the deployment guide. On-device redaction is best effort,
            not a guarantee: its excerpt, locator, target host, or optional note could still contain
            personal or confidential information. The app shows the report before sending it; do not
            confirm if it contains anything you do not want to share.
          </p>
        </Section>

        <Section title="When data leaves your device">
          <p>
            Allowed AI requests are forwarded to the provider you configured. The update checker
            contacts Bouclier&apos;s hosting layer. The SIEM webhook sends detection metadata to
            infrastructure controlled by the organization&apos;s IT administrator, only when that
            administrator configures it.
          </p>
          <p className="mt-3">
            A false-positive report reaches Bouclier.ai only when you choose it, review the rendered
            payload, and confirm. The report carries the app version, matched pattern names and
            count, signal scores, target host, locator, a salted fingerprint, your optional note,
            and the best-effort-redacted excerpt. It can also include the best-effort-redacted
            classifier passage that most influenced the score and that passage&apos;s score. The
            application payload does not add your IP address or user-agent, although the hosting
            layer necessarily receives ordinary transport metadata for the HTTP request.
          </p>
        </Section>

        <Section title="Injection inspection method">
          <p>
            The Software inspects eligible routed request bodies on-device when they contain a
            supported untrusted-content shape (tool results and other model-visible text the agent
            fetched itself). Principal-only requests bypass injection scoring in normal mode. When a
            supported untrusted shape is present, principal spans may also be scored and logged for
            context but cannot trigger a normal-mode refusal. A managed strict posture can change
            that principal policy. Inspection reads the request in memory for the duration of that
            request; Bouclier does not store the full request or send it to its own servers. When a
            finding crosses the refusal threshold and blocking is enabled, the request is refused
            locally with a 422 — it never reaches the AI provider. Otherwise its model-visible body
            is forwarded byte-for-byte to that provider.
          </p>
          <p className="mt-3">
            Prompt-body bytes and end-to-end headers such as Authorization, x-api-key, and trace IDs
            are preserved. Host and Content-Length are regenerated for the upstream connection, and
            hop-by-hop and Proxy-Authorization headers are stripped. The body is delivered unchanged
            or its request is refused, never rewritten. End-to-end tests pin these boundaries in the
            public repository.
          </p>
          <p className="mt-3 text-sm">
            The attachment-PII detection engine described in earlier versions of this policy is not
            on any live request path.
          </p>
        </Section>

        <Section title="Auditing">
          The Software is open source under Apache 2.0; the entire codebase, including the regex
          patterns, the on-device classifier integration, and the test suite, is published at{" "}
          <a
            href="https://github.com/SuperstellarLLC/bouclier-ai"
            className="text-bouclier hover:underline"
          >
            github.com/SuperstellarLLC/bouclier-ai
          </a>
          . You can audit, fork, rebuild, and verify the behaviour of every component. No additional
          commercial audit programme is offered.
        </Section>

        <Section title="Your rights">
          <p>
            Most data the Software generates lives on your device and is under your control: stored
            under <code>~/Library/Application Support/ai.bouclier.app/</code> and removable by
            deleting that application support directory. Removing the app bundle does not
            automatically delete this data. The Site&apos;s download record has no user identifier.
            An optional false-positive report may contain information about you despite redaction;
            if you kept its fingerprint or report preview, include that when contacting us about
            access or deletion.
          </p>
          <p className="mt-3 text-sm">
            For data subjects in Switzerland (revised FADP) and the European Economic Area (GDPR),
            the rights of access, rectification, deletion, restriction of processing, objection, and
            data portability may apply to personal data we hold. Contact us using the address below;
            we may need enough information to locate a report without collecting a new identifier.
          </p>
        </Section>

        <Section title="Children">
          The Software is not directed at children under the age of sixteen (16). We do not
          knowingly solicit personal data from children; do not submit a false-positive report on
          behalf of a child.
        </Section>

        <Section title="Sub-processors">
          The Site is hosted on Vercel Inc. infrastructure. Vercel may log standard HTTP request
          metadata at its edge nodes (transit IP, request path, status code, timestamp) for periods
          set by its policy. When configured, Upstash stores the application-level download counters
          and rolling events. It also holds a submitted report&apos;s proof-of-work timestamp,
          fingerprint, and nonce for 180 seconds to prevent replay. Neon or Vercel Postgres stores
          optional false-positive reports. Those services receive the scoped fields described above;
          they do not receive prompt traffic automatically from the gateway.
        </Section>

        <Section title="Governing law and exclusive jurisdiction">
          <p>
            This Notice is governed by Swiss law. Any dispute arising out of or relating to the
            processing of personal data described in this Notice shall be subject to the exclusive
            jurisdiction of the ordinary courts of the Canton of Zug, Switzerland, save that any
            non-waivable right granted to a data subject by mandatorily-applicable consumer or
            data-protection law of the subject&apos;s habitual residence is preserved.
          </p>
        </Section>

        <Section title="Changes to this Notice">
          We may update this Notice at any time by publishing a revised version on the Site. The
          &quot;Last updated&quot; date above identifies the current version. Material changes
          affecting how personal data is processed will be summarised in the public project
          changelog and the release notes linked from the update channel.
        </Section>

        <Section title="Contact">
          <p>
            Contact:{" "}
            <a href="mailto:apps@superstellar.io" className="text-bouclier hover:underline">
              apps@superstellar.io
            </a>
          </p>
          <p className="mt-3 text-sm">
            Postal address for written privacy requests will be provided on request.
          </p>
        </Section>
      </article>

      <footer className="border-border border-t py-8">
        <div className="text-text-secondary mx-auto flex max-w-3xl items-center justify-between px-6 text-sm">
          <span>Bouclier.ai</span>
          <div className="flex gap-6">
            <Link href="/" className="hover:text-text transition-colors">
              Home
            </Link>
            <Link href="/terms" className="hover:text-text transition-colors">
              Terms
            </Link>
          </div>
        </div>
      </footer>
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-12">
      <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
      <div className="text-text-secondary mt-3 leading-relaxed">{children}</div>
    </section>
  );
}
