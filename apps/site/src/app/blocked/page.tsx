import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

import { APP_URL } from "@/lib/constants";

export const metadata: Metadata = {
  title: "Request refused",
  description:
    "Why Bouclier.ai refused a request after content crossed the configured detector policy.",
  alternates: { canonical: `${APP_URL}/blocked` },
  openGraph: {
    title: "Bouclier.ai request refused",
    description:
      "Why Bouclier.ai refused a request after untrusted content crossed the enforcement threshold.",
    url: `${APP_URL}/blocked`,
    type: "article",
  },
};

export default function BlockedPage() {
  return (
    <main className="min-h-screen bg-white">
      {/* Nav */}
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
          </Link>
          <div className="text-text-secondary flex gap-6 text-sm">
            <Link href="/" className="hover:text-text transition-colors">
              Home
            </Link>
            <Link href="/privacy" className="hover:text-text transition-colors">
              Privacy
            </Link>
          </div>
        </div>
      </nav>

      <div className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-3xl font-bold tracking-tight">Your request was refused</h1>
        <p className="text-text-secondary mt-4 text-lg">
          Bouclier.ai found instructions that crossed this install&apos;s configured detector
          policy, so it stopped the request before it reached the provider. In normal Blocking mode,
          only a span classified as <strong>untrusted</strong> can cause this refusal. A managed
          strict policy can also enforce findings in principal or attributed local-read content; the
          error&apos;s locator identifies the span that drove the decision.
        </p>

        {/* What actually happened */}
        <div className="mt-10 rounded-xl border border-amber-200 bg-amber-50 p-6">
          <p className="text-sm font-medium text-amber-800">Your agent received:</p>
          <code className="text-text mt-3 block overflow-x-auto rounded-lg bg-white p-4 font-mono text-xs leading-relaxed">
            HTTP/1.1 422 Unprocessable Entity
            <br />
            {`{"type":"error","error":{"type":"bouclier_injection_blocked",`}
            <br />
            {`  "locator":"messages[2].content[0].tool_result", …}}`}
          </code>
          <p className="mt-3 text-sm text-amber-700">
            The <code className="rounded bg-white px-1 py-0.5">locator</code> is the exact JSON path
            the content came from, so you can find it. Nothing was spliced into the prompt body —
            Bouclier either forwards those body bytes unchanged or refuses the request outright.
          </p>
        </div>

        {/* Not a login problem */}
        <div className="border-border mt-6 rounded-xl border p-6">
          <h2 className="text-sm font-semibold">Not a login problem</h2>
          <p className="text-text-secondary mt-2 text-sm leading-relaxed">
            A refusal comes back as{" "}
            <code className="bg-surface rounded px-1 py-0.5">422 Unprocessable Entity</code> — a
            policy response, not an authentication error. If your coding agent reacted by suggesting
            you re-authenticate (&quot;Please run{" "}
            <code className="bg-surface rounded px-1 py-0.5">/login</code>&quot;), that was a
            mislabel: Bouclier deliberately avoids{" "}
            <code className="bg-surface rounded px-1 py-0.5">401</code> and{" "}
            <code className="bg-surface rounded px-1 py-0.5">403</code>, which agents read as a
            credential failure. Your login is fine — the refused request does not end the session,
            and later clean requests can still go through.
          </p>
        </div>

        {/* Request-local provenance */}
        <div className="border-border mt-6 rounded-xl border p-6">
          <h2 className="text-sm font-semibold">How Bouclier classified the span</h2>
          <p className="text-text-secondary mt-2 text-sm leading-relaxed">
            Bouclier uses the origin markers in routed requests to separate principal text from
            untrusted tool output. Your own prompt and system prompt are forwarded unchanged and{" "}
            <strong>never blocked</strong> in normal mode — you are allowed to discuss jailbreaks,
            paste advisories, and test payloads against your own model. If a request also contains
            supported untrusted content, principal spans may be scored and logged for context.
            Separately, only a <code className="bg-surface rounded px-1 py-0.5">Read</code> /{" "}
            <code className="bg-surface rounded px-1 py-0.5">NotebookRead</code> result positively
            linked to a canonical, non-vendored path under the active workspace is classified as
            authored. A project-local path alone is not enough, and missing or ambiguous attribution
            stays untrusted.
          </p>
          <p className="text-text-secondary mt-3 text-sm leading-relaxed">
            These are request-local classifications, not proof of who wrote the bytes. Bouclier does
            not track file taint or write history across requests. External content silently saved
            into an otherwise eligible workspace path can therefore receive the authored
            classification on a later linked read. Enable managed strict mode or disable
            authored-read trust when every tool result must remain enforceable.
          </p>
        </div>

        {/* False positive */}
        <h2 className="mt-16 text-2xl font-bold tracking-tight">False positive?</h2>
        <p className="text-text-secondary mt-2 text-sm leading-relaxed">
          Detection is best-effort and pattern-based — legitimate content sometimes looks like an
          attack (source code, security write-ups, and email or prompt templates all quote the
          phrases attackers use). Review the matching activity entry first. If the span is safe,
          choose <strong>Unblock</strong>: Bouclier releases that exact span while leaving
          enforcement active for everything else. You can re-arm released spans in Settings.
        </p>
        <div className="mt-6 grid gap-4 sm:grid-cols-3">
          <div className="border-border rounded-xl border p-5">
            <h3 className="text-sm font-semibold">Review and unblock</h3>
            <p className="text-text-secondary mt-2 text-sm">
              Open the activity log, inspect the locator and score, then choose Unblock on that
              entry to release only the reviewed span.
            </p>
          </div>
          <div className="border-border rounded-xl border p-5">
            <h3 className="text-sm font-semibold">Report after review</h3>
            <p className="text-text-secondary mt-2 text-sm">
              If capture was enabled, choose Report false positive. The app redacts the sample and
              shows the complete report for confirmation before sending it.
            </p>
          </div>
          <div className="border-border rounded-xl border p-5">
            <h3 className="text-sm font-semibold">Monitor as a fallback</h3>
            <p className="text-text-secondary mt-2 text-sm">
              If you cannot review individual spans, switch to monitor mode temporarily. Findings
              are still detected and logged, but requests are not refused.
            </p>
          </div>
        </div>

        <div className="border-border bg-surface mt-6 rounded-xl border p-5">
          <p className="text-text-secondary text-sm">
            If the reviewed in-app report is unavailable, email us with no prompt content or secrets
            so we can help diagnose the match safely.
          </p>
          <a
            href="mailto:apps@superstellar.io"
            className="border-border text-text mt-3 inline-flex rounded-lg border bg-white px-4 py-2 text-sm font-medium shadow-sm transition-all hover:shadow-md"
          >
            Report a false positive
          </a>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-border border-t py-8">
        <div className="text-text-secondary mx-auto flex max-w-3xl items-center justify-between px-6 text-sm">
          <span>Bouclier.ai</span>
          <div className="flex gap-6">
            <Link href="/" className="hover:text-text transition-colors">
              Home
            </Link>
            <Link href="/privacy" className="hover:text-text transition-colors">
              Privacy
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
