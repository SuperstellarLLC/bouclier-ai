import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy Policy",
};

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-white">
      <nav className="border-border border-b">
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
        <p className="text-text-secondary mt-2 text-sm">Last updated: 27 May 2026</p>

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
            Bouclier.ai runs entirely on your device. The gateway inspects requests locally — for
            prompt-injection patterns in tool output, and for a managed secret&apos;s real value —
            and never stores, transmits, or logs your prompts or responses anywhere. The app
            collects no personal data, has no analytics, no crash reporting, and no user accounts.
            The only information that ever reaches a bouclier.ai server is a single anonymous
            timestamp when you click the Download button on this marketing site — full scope
            described below.
          </p>
        </div>

        <Section title="What Bouclier.ai does">
          Bouclier.ai runs a local gateway on your Mac. You point your AI agent&apos;s SDK at it (
          <code>ANTHROPIC_BASE_URL</code> / <code>OPENAI_BASE_URL</code>) instead of the provider
          directly; the gateway re-issues each request to the real provider over TLS and streams the
          response back. There is no system-wide traffic interception, no certificate authority, and
          no decryption of traffic the gateway wasn&apos;t explicitly pointed at. Text prompt bodies
          and request headers are forwarded byte-for-byte; the only content the Software ever
          modifies is a managed secret&apos;s real value, which is scrubbed to a placeholder on the
          way out (see &quot;What reaches the model&quot; on the homepage) and restored in the
          response.
        </Section>

        <Section title="Providers reached">
          <p>The gateway routes requests to whichever provider the request targets. Built in:</p>
          <div className="border-border bg-surface mt-3 rounded-lg border px-4 py-3 font-mono text-sm">
            api.openai.com, api.anthropic.com
          </div>
          <p className="text-text-secondary mt-3 text-sm">
            Organizations using MDM can override the upstream host/port via managed app
            configuration.
          </p>
        </Section>

        <Section title="Network connections">
          <ol className="list-decimal space-y-3 pl-5">
            <li>
              <strong>AI API forwarding</strong> — forwarding your requests to their intended
              destination. A managed secret&apos;s real value is scrubbed to a placeholder before
              the request leaves the gateway and restored in the response; nothing else is modified.
            </li>
            <li>
              <strong>Update check</strong> — checking for software updates via appcast.xml hosted
              on bouclier.ai. Transmits app version, macOS version, CPU architecture, and preferred
              language. No personal data or request content.
            </li>
            <li>
              <strong>SIEM webhook (enterprise only)</strong> — if and only if configured by an
              organization&apos;s IT administrator via MDM, secret-keeper event metadata (timestamp,
              host, event kind) is sent to that organization-controlled endpoint. Never enabled by
              default. Cannot be configured by the user.
            </li>
          </ol>
        </Section>

        <Section title="Marketing site (bouclier.ai)">
          <p>
            When you click the &quot;Download&quot; button on bouclier.ai, the server records a
            single anonymous event consisting of <strong>(a) the time of the click</strong>,{" "}
            <strong>(b) the requested app version</strong>, and{" "}
            <strong>(c) the channel string</strong> (e.g. &quot;site&quot;) that the link carries.
            That&apos;s it.
          </p>
          <p className="mt-3">We do not record, store, or transmit:</p>
          <ul className="mt-2 list-disc space-y-1 pl-5">
            <li>your IP address;</li>
            <li>your user-agent string or device fingerprint;</li>
            <li>the referring page or any UTM parameter;</li>
            <li>your country or any geolocation derived from the request;</li>
            <li>any cookie, session token, or other identifier.</li>
          </ul>
          <p className="mt-3 text-sm">
            The event is recorded so we can see whether anyone is downloading the beta. It cannot be
            linked back to you. The marketing site does not use Google Analytics, Plausible,
            PostHog, Mixpanel, Segment, Fathom, or any equivalent product analytics tool, and never
            has.
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
                <strong>Daily stats</strong> — date, requests scanned, secrets scrubbed/blocked.
                Retained 365 days.
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Managed secret values</strong> — macOS Keychain (encrypted at rest),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly. Never written to disk in plaintext,
                never logged.
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

        <Section title="Data we collect">
          None. Bouclier.ai has no user accounts, no analytics, no crash reporting, and no usage
          telemetry.
        </Section>

        <Section title="Data we share">
          None. The SIEM webhook feature sends metadata to infrastructure controlled by the
          organization&apos;s IT administrator, not to Bouclier.ai or any third party.
        </Section>

        <Section title="Secret scrub / restore method">
          <p>
            A managed secret&apos;s real value is detected by exact match against the value you
            stored in Keychain (not a heuristic or classifier) and replaced with an opaque
            placeholder before the request reaches the model provider. The matching response is
            scanned for the placeholder and restored to the real value so your local tools keep
            working. Requests and responses containing no managed secret value are forwarded
            byte-for-byte, untouched.
          </p>
          <p className="mt-3">
            Text prompt bodies and HTTP request headers are otherwise forwarded byte-for-byte; the
            Software does not modify outbound prompts or headers beyond the secret-scrub
            substitution described above. This is pinned by an end-to-end test in the public
            repository.
          </p>
          <p className="mt-3 text-sm">
            The Software also inspects request bodies on-device for prompt-injection patterns in
            untrusted content (tool results and other model-visible text the agent fetched itself).
            This inspection reads the request but never stores or transmits it; a flagged request is
            refused locally with a 403, never rewritten. The attachment-PII detection engine
            described in earlier versions of this policy is not on any live request path.
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
            Because no personal data is collected by the Software or transmitted to any
            Bouclier.ai-controlled server, there is no profile, account, or stored record we could
            give you access to, rectify, port, or erase on your behalf. The data the Software
            generates lives on your device and is fully under your control: stored under{" "}
            <code>~/Library/Application Support/ai.bouclier.app/</code> and removable at any time by
            uninstalling the app or by deleting the application support directory.
          </p>
          <p className="mt-3 text-sm">
            For data subjects in Switzerland (revised FADP) and the European Economic Area (GDPR),
            the rights of access, rectification, deletion, restriction of processing, objection, and
            data portability formally apply to any personal data we hold — which, as described
            above, is none beyond a single anonymous click event on the Site. You may nevertheless
            contact us using the address below to confirm this status.
          </p>
        </Section>

        <Section title="Children">
          The Software is not directed at children under the age of sixteen (16). We do not
          knowingly collect data from anyone, including children.
        </Section>

        <Section title="Sub-processors">
          The Site is hosted on Vercel Inc. infrastructure. Vercel may, in the ordinary course of
          delivering web pages, log standard HTTP request metadata at its edge nodes (transit IP,
          request path, status code, timestamp) for periods set by its own policy. We do not
          aggregate, analyse, or persist that data on our side. No other sub-processor receives any
          information generated by the Software or the Site.
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
          affecting how personal data is processed will be summarised in the project changelog and,
          where reasonably practicable, surfaced in the in-app &quot;What&apos;s new&quot; sheet
          shown on first launch of a new version.
        </Section>

        <Section title="Contact">
          <p>Privacy: privacy@bouclier.ai</p>
          <p>Support: support@bouclier.ai</p>
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
