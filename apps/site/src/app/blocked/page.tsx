import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Request blocked",
  description:
    "Why Bouclier.ai refused a request: untrusted tool output contained instructions aimed at your model.",
};

export default function BlockedPage() {
  return (
    <main className="min-h-screen bg-white">
      {/* Nav */}
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
          Bouclier.ai flagged instructions inside <strong>untrusted content</strong> on its way into
          your model — a tool result, a fetched page, a file your agent read. Nobody in your session
          typed it, and this install has enforcement enabled, so the request was stopped before it
          reached the provider.
        </p>

        {/* What actually happened */}
        <div className="mt-10 rounded-xl border border-amber-200 bg-amber-50 p-6">
          <p className="text-sm font-medium text-amber-800">Your agent received:</p>
          <code className="text-text mt-3 block overflow-x-auto rounded-lg bg-white p-4 font-mono text-xs leading-relaxed">
            HTTP/1.1 403 Forbidden
            <br />
            {`{"type":"error","error":{"type":"bouclier_injection_blocked",`}
            <br />
            {`  "locator":"messages[2].content[0].tool_result", …}}`}
          </code>
          <p className="mt-3 text-sm text-amber-700">
            The <code className="rounded bg-white px-1 py-0.5">locator</code> is the exact JSON path
            the content came from, so you can find it. Nothing was rewritten — Bouclier either
            forwards a request byte-for-byte or refuses it outright.
          </p>
        </div>

        {/* Why yours wasn't the problem */}
        <div className="border-border mt-6 rounded-xl border p-6">
          <h2 className="text-sm font-semibold">This was not something you typed</h2>
          <p className="text-text-secondary mt-2 text-sm leading-relaxed">
            Bouclier splits every request by origin. Your own prompt and system prompt are scanned
            for the activity log but <strong>never blocked</strong> — you are allowed to discuss
            jailbreaks, paste advisories, and test payloads against your own model. Only content
            that arrived from a tool can trigger a refusal.
          </p>
        </div>

        {/* False positive */}
        <h2 className="mt-16 text-2xl font-bold tracking-tight">False positive?</h2>
        <p className="text-text-secondary mt-2 text-sm leading-relaxed">
          Detection is best-effort and pattern-based — legitimate content sometimes looks like an
          attack (source code, security write-ups, and email or prompt templates all quote the
          phrases attackers use). If this was a false positive, you can turn enforcement off and run
          in monitor mode (detect and log without blocking) in the menu-bar app.
        </p>
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          <div className="border-border rounded-xl border p-5">
            <h3 className="text-sm font-semibold">Check your logs</h3>
            <p className="text-text-secondary mt-2 text-sm">
              Open the Bouclier.ai menu-bar app and review the activity log — each event shows where
              in the request the match was and its score.
            </p>
          </div>
          <div className="border-border rounded-xl border p-5">
            <h3 className="text-sm font-semibold">Export diagnostics</h3>
            <p className="text-text-secondary mt-2 text-sm">
              Use the &quot;Export Diagnostics&quot; action in the menu bar to generate a
              privacy-scrubbed bundle you can share with us.
            </p>
          </div>
        </div>

        <div className="border-border bg-surface mt-6 rounded-xl border p-5">
          <p className="text-text-secondary text-sm">
            If you believe legitimate content is being flagged, let us know so we can tune the
            detection.
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
          </div>
        </div>
      </footer>
    </main>
  );
}
