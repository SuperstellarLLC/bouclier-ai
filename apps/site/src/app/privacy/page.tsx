import type { Metadata } from "next";
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
            <img
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
            <Link href="/blocked" className="hover:text-text transition-colors">
              Blocked
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-3xl font-bold tracking-tight">Privacy Policy</h1>
        <p className="text-text-secondary mt-2 text-sm">Last updated: April 2026</p>

        {/* Summary box */}
        <div className="border-accent-green/30 mt-10 rounded-xl border-2 bg-emerald-50 p-6">
          <p className="font-medium text-emerald-900">
            Bouclier.ai processes all data locally on your device. We do not collect personal data.
            We do not operate servers that receive your data. We have no analytics, no telemetry,
            and no user accounts.
          </p>
        </div>

        <Section title="What Bouclier.ai does">
          Bouclier.ai is a local network proxy that scans AI API traffic for prompt injection
          attacks. It intercepts HTTPS connections to a specific set of AI API domains, decrypts
          them using a locally-generated certificate authority, inspects the request content for
          injection patterns, and forwards the request to the intended destination.
        </Section>

        <Section title="Intercepted domains">
          <p>
            Bouclier.ai only intercepts traffic to these specific domains. All other network traffic
            is completely untouched:
          </p>
          <div className="border-border bg-surface mt-3 rounded-lg border px-4 py-3 font-mono text-sm">
            api.openai.com, api.anthropic.com, api.cohere.com, api.mistral.ai,
            generativelanguage.googleapis.com, api.together.xyz, api.groq.com, api.perplexity.ai,
            api.fireworks.ai, openrouter.ai
          </div>
          <p className="text-text-secondary mt-3 text-sm">
            Organizations using MDM can add additional domains via managed app configuration.
          </p>
        </Section>

        <Section title="Network connections">
          <ol className="list-decimal space-y-3 pl-5">
            <li>
              <strong>AI API forwarding</strong> — forwarding your requests to their intended
              destination. Content may be modified if a prompt injection is detected.
            </li>
            <li>
              <strong>Update check</strong> — checking for software updates via appcast.xml hosted
              on bouclier.ai. Transmits app version, macOS version, CPU architecture, and preferred
              language. No personal data or request content.
            </li>
            <li>
              <strong>SIEM webhook (enterprise only)</strong> — if and only if configured by an
              organization&apos;s IT administrator via MDM, scan event metadata (timestamp, host,
              pattern, severity) is sent to that organization-controlled endpoint. Never enabled by
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
                <strong>Scan logs</strong> — timestamp, source, target host, detection status,
                pattern IDs, severity, request size. No request body content. Auto-deleted after 30
                days.
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Daily stats</strong> — date, requests scanned, injections blocked. Retained
                365 days.
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>CA certificate</strong> — public PEM file (not sensitive).
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>CA private key</strong> — macOS Keychain (encrypted at rest),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly. Never written to disk in plaintext.
              </span>
            </li>
            <li className="flex gap-2">
              <span className="bg-text-secondary mt-2 h-1 w-1 shrink-0 rounded-full" />
              <span>
                <strong>Preferences</strong> — proxy port, notifications, launch-at-login. Via
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

        <Section title="Detection method">
          Bouclier.ai uses deterministic regex pattern matching, heuristic scoring, and on-device
          Meta Llama Prompt Guard 2 classification for additional prompt attack detection. No
          request content is sent to any external service.
        </Section>

        <Section title="Attribution">
          Built with Llama. Bouclier.ai uses Meta Llama Prompt Guard 2 locally on your Mac. The
          bundled legal notice and Llama 4 Community License are distributed with the app and in
          this repository.
        </Section>

        <Section title="Certificate authority">
          A local root CA is generated on your device during setup, used solely to decrypt AI API
          traffic for inspection. The private key never leaves your device. Removable at any time
          via Settings.
        </Section>

        <Section title="Auditing">
          Enterprise customers can request a full source code audit. Contact us for details.
        </Section>

        <Section title="Contact">
          <p>Privacy: privacy@bouclier.ai</p>
          <p>Support: support@bouclier.ai</p>
        </Section>
      </article>

      <footer className="border-border border-t py-8">
        <div className="text-text-secondary mx-auto flex max-w-3xl items-center justify-between px-6 text-sm">
          <span>Bouclier.ai</span>
          <div className="flex gap-6">
            <Link href="/" className="hover:text-text transition-colors">
              Home
            </Link>
            <Link href="/blocked" className="hover:text-text transition-colors">
              Blocked
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
