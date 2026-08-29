import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

import { APP_URL } from "@/lib/constants";

const DESCRIPTION =
  "Terms for Bouclier.ai, including its experimental limitations and open-source licensing boundary.";

export const metadata: Metadata = {
  title: "Terms of Use",
  description: DESCRIPTION,
  alternates: { canonical: `${APP_URL}/terms` },
  openGraph: {
    title: "Bouclier.ai Terms of Use",
    description: DESCRIPTION,
    url: `${APP_URL}/terms`,
    type: "article",
  },
};

export default function TermsPage() {
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
            <Link href="/privacy" className="hover:text-text transition-colors">
              Privacy
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-3xl font-bold tracking-tight">Terms of Use</h1>
        <p className="text-text-secondary mt-2 text-sm">Last updated: 29 August 2026</p>

        {/* Loud prototype banner — anyone evaluating the software must see this first. */}
        <div className="mt-10 rounded-xl border-2 border-amber-300 bg-amber-50 p-6">
          <p className="font-semibold text-amber-900">
            Bouclier.ai is experimental, pre-1.0 software.
          </p>
          <p className="mt-2 text-sm text-amber-900">
            Detection is best-effort and has not been independently validated or certified for
            regulated or safety-critical workloads. False negatives and false positives will occur.
            Evaluate the Software against your own threat model, use additional safeguards, and do
            not rely on it as the sole control where failure could cause harm, financial loss, or
            regulatory non-compliance. The source code is offered under open-source licences; those
            licences, not these Terms, govern your rights to use, copy, modify, and distribute the
            licensed code.
          </p>
        </div>

        <Section title="1. Acceptance">
          <p>
            These Terms are between you and Superstellar GmbH (English: Superstellar LLC;
            &quot;Superstellar&quot;, &quot;we&quot;, or &quot;us&quot;). By accessing the website
            at bouclier.ai (the &quot;Site&quot;) or using distribution, update, reporting, or other
            services that we provide for Bouclier.ai (the &quot;Software&quot;), you agree to these
            Terms of Use. These Terms also state important limitations and disclaimers for Software
            distributed through the Site. Your rights in the Software&apos;s source code and its
            open-source components are governed by the applicable licences. If these Terms conflict
            with an applicable open-source licence, that licence controls for the licensed material.
            Use of code under such a licence is not conditioned on accepting these Terms. If you do
            not agree to these Terms, do not use the Site or our related services.
          </p>
        </Section>

        <Section title="2. Experimental software and source licensing">
          <p>
            The Software is an experimental security and machine-learning project whose source code
            is open source under Apache 2.0. Signed release builds also include the Meta Prompt
            Guard 2 model under the separate Llama 4 Community License. The Software is pre-1.0 and
            comes without a service-level agreement, paid support tier, professional services,
            uptime commitment, certification, or assurance of fitness for any operational purpose.
          </p>
          <p className="mt-3">
            Bouclier&apos;s source code is published under the Apache License, Version 2.0, except
            where a file or bundled component identifies another licence. The applicable licence
            governs your rights to use, reproduce, modify, and distribute that material. These Terms
            do not add a field-of-use restriction to open-source code. Operational use is not an
            endorsement or warranty: you remain responsible for evaluating the Software, testing it
            in your environment, and choosing safeguards appropriate to the consequences of failure.
            Security testing, academic engagement, and contributor feedback are welcome.
          </p>
          <p className="mt-3">
            Pre-1.0 version numbering reflects this status. APIs, detection behaviour, file formats,
            default settings, the detection pattern set, the refusal thresholds, and the scope of
            inspected traffic may change without notice between releases. Features described in
            marketing materials, documentation, the README, the changelog, or in-app text may be
            removed, altered, or replaced at any time. Do not assume that a specific behaviour will
            persist across releases without testing the version you deploy.
          </p>
        </Section>

        <Section title="3. No warranty">
          <p className="font-semibold">
            THE SOFTWARE IS PROVIDED &quot;AS IS&quot; AND &quot;AS AVAILABLE&quot;, WITHOUT
            WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE WARRANTIES OF
            MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS,
            NON-INFRINGEMENT, OR ANY WARRANTY ARISING OUT OF COURSE OF DEALING OR USAGE OF TRADE.
          </p>
          <p className="mt-3">
            Without limiting the foregoing, we make no warranty that the Software will detect or
            block any specific prompt injection, preserve any specific behaviour across sessions or
            releases, be free of errors, operate without interruption, be secure against any
            specific threat, interoperate with any third-party tool or service, or meet any
            regulatory or compliance requirement.
          </p>
        </Section>

        <Section title="4. Detection is best-effort">
          <p>
            The Software inspects requests for prompt-injection patterns in <em>untrusted</em>{" "}
            content — tool results and other model-visible text your agent fetched rather than text
            you typed. This detection is probabilistic, pattern-based, and best-effort: it has the
            false-positive and false-negative characteristics typical of such systems, and a
            determined attacker can evade it. It is defence-in-depth, not a guarantee, and must not
            be relied upon as the sole control protecting you from prompt injection or data
            exfiltration. Specifically and without limitation:
          </p>
          <ul className="mt-3 list-disc space-y-2 pl-5">
            <li>
              <strong>Scope.</strong> Only traffic that is explicitly routed through the
              Software&apos;s gateway (by configuring <code>ANTHROPIC_BASE_URL</code> /{" "}
              <code>OPENAI_BASE_URL</code>
              or equivalent, or via the Software&apos;s own shell/environment wiring) is in scope.
              Any process, tool, or connection that does not route through the gateway is entirely
              outside the Software&apos;s reach and unaffected by it.
            </li>
            <li>
              <strong>Evadable.</strong> The detector matches known attack families and the cheap
              obfuscations around them. A payload deliberately shaped to slip past it can and will
              succeed. A clean pass is not evidence of safety.
            </li>
            <li>
              <strong>Monitor by default.</strong> Out of the box the Software scores supported
              untrusted-content shapes within its inspection limit and logs findings but does not
              refuse them. Principal-only requests bypass injection scoring in normal mode. Blocking
              (refusing a request that crosses the refusal threshold) is opt-in, per install or via
              MDM. Monitor mode does not enforce detector findings, although the gateway can still
              reject malformed requests or bodies above its separate transport limit.
            </li>
            <li>
              <strong>Body size cap.</strong> Requests above a configured size threshold are not
              fully inspected. For a valid supported envelope, the Software scores an evenly
              distributed sample of at most 24 untrusted-content windows. A finding in that sample
              can be refused when Blocking is enabled; a clean or inconclusive sample is forwarded
              with a visible partial-coverage warning in either mode. Independently, the gateway
              rejects any body above its 64 MiB transport limit with 413.
            </li>
          </ul>
          <p className="mt-3 text-sm">
            The Software never modifies a model-visible request body: a request selected for refusal
            is stopped locally with a 422, and its body is never rewritten. Your own prompts are
            forwarded unchanged and cannot trigger a refusal in normal mode; a managed strict
            posture can change that principal policy. The attachment-PII detection engine described
            in earlier versions of these Terms is not on any live request path.
          </p>
        </Section>

        <Section title="5. No compliance claim">
          <p>
            Nothing in the Software, the website, the documentation, or related materials
            constitutes a representation that the Software, alone or in combination with anything
            else, will cause its user to comply with any law, regulation, contract, or industry
            standard, including but not limited to the EU General Data Protection Regulation, the
            Health Insurance Portability and Accountability Act, the Payment Card Industry Data
            Security Standard, the California Consumer Privacy Act, the EU AI Act, SOC 2, ISO 27001,
            or any equivalent framework. Compliance with such instruments is the sole responsibility
            of the user and the user&apos;s organisation.
          </p>
        </Section>

        <Section title="6. Your responsibilities">
          <ul className="list-disc space-y-2 pl-5">
            <li>
              You are solely responsible for the content of the prompts you send to AI providers and
              for the use you make of their responses, whether or not the Software was active at the
              time.
            </li>
            <li>
              You are solely responsible for evaluating whether the Software is appropriate for your
              environment, your data, and your obligations. Where a missed injection or a false
              positive could cause harm to you, your employer, your customers, or another party,
              treat Bouclier as defence in depth, perform your own risk review, and use additional
              controls rather than relying on it as the sole safeguard.
            </li>
            <li>
              You are solely responsible for the configuration of every Software setting, including
              MDM-managed values, whether blocking is enabled, and which processes are routed
              through the gateway. Misconfiguration, running in monitor mode, or simply not routing
              a given tool through the gateway, may cause an injection to reach your agent
              uninspected or unblocked.
            </li>
            <li>
              You must comply with the terms of service of every AI provider you send traffic to.
              The Software does not relieve you of obligations arising under your contracts with
              those providers.
            </li>
          </ul>
        </Section>

        <Section title="7. Limitation of liability">
          <p className="font-semibold">
            TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL SUPERSTELLAR, ITS
            CONTRIBUTORS, AGENTS, AFFILIATES, OR LICENSORS BE LIABLE FOR ANY INDIRECT, INCIDENTAL,
            SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS, REVENUE, DATA,
            GOODWILL, USE, OR OTHER INTANGIBLE LOSSES, ARISING OUT OF OR RELATING TO YOUR USE OF OR
            INABILITY TO USE THE SOFTWARE, WHETHER BASED ON WARRANTY, CONTRACT, TORT (INCLUDING
            NEGLIGENCE), PRODUCT LIABILITY, OR ANY OTHER LEGAL THEORY, AND WHETHER OR NOT WE HAVE
            BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
          </p>
          <p className="mt-3 font-semibold">
            OUR TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATING TO THE SOFTWARE, REGARDLESS OF
            THE FORM OF ACTION, SHALL NOT EXCEED FIFTY EUROS (€50) OR THE AMOUNT YOU HAVE PAID TO
            SUPERSTELLAR FOR THE SOFTWARE IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE
            TO THE LIABILITY, WHICHEVER IS LOWER.
          </p>
          <p className="mt-3 text-sm">
            Some jurisdictions do not allow the exclusion or limitation of certain damages or
            warranties. In such jurisdictions, the foregoing exclusions and limitations apply to the
            maximum extent permitted by law.
          </p>
        </Section>

        <Section title="8. Indemnification">
          <p>
            To the extent permitted by applicable law, you agree to indemnify, defend, and hold
            harmless Superstellar, its contributors, agents, affiliates, and licensors from claims
            arising from content you submit through the Site or our reporting services, your
            violation of these Terms, your violation of a third-party right, or your violation of
            applicable law. This section does not alter rights granted by an open-source licence.
          </p>
        </Section>

        <Section title="9. Local detection and limited data flows">
          <p>
            The Software performs detection locally on your device. It does not automatically send
            prompt content, attachment content, or audit logs to Bouclier.ai, and it has no passive
            app analytics or crash reporting. Allowed requests are still forwarded to the AI
            provider you configured. If you explicitly submit a false-positive report, its
            best-effort-redacted excerpt and detection metadata are sent to Bouclier.ai after you
            review the payload. Site requests, update checks, optional reports, and all other
            outbound connections are described in the{" "}
            <Link href="/privacy" className="text-bouclier hover:underline">
              Privacy Notice
            </Link>
            . We cannot recover or restore content kept only on your device, undo provider actions,
            or intervene in interactions between your computer and those providers.
          </p>
        </Section>

        <Section title="10. Third-party providers">
          <p>
            The Software re-issues requests you route through its gateway to third-party AI
            providers. Model-visible body bytes and end-to-end headers such as Authorization are
            preserved. As a correct HTTP proxy, the Software rewrites Host and Content-Length and
            strips hop-by-hop and Proxy-Authorization headers. It does not rewrite the prompt body:
            that body is forwarded unchanged or, when injection is detected and blocking is enabled,
            its request is refused locally as described in Section 4. We have no control over those
            providers, their terms, their data handling, their availability, or their pricing. Your
            use of those providers is governed by your agreement with each of them. Content
            delivered to each provider is governed by that provider&apos;s own terms.
          </p>
        </Section>

        <Section title="11. Third-party and open-source components">
          <p>
            The Software incorporates third-party and open-source components, including (without
            limitation) the Meta Llama Prompt Guard 2 integration (&quot;Built with Llama&quot;; the
            signed release build bundles the model under the Llama 4 Community License and runs
            inference locally through CoreML), Sparkle, GRDB, SwiftNIO, and swift-transformers. If
            the model cannot load, detection continues with the local pattern tier. Corresponding
            licence and notice texts are bundled with signed releases and indexed in the repository
            at <code>LICENSES/THIRD-PARTY-NOTICES.txt</code>. Each component remains governed by its
            respective licence.
          </p>
        </Section>

        <Section title="12. Updates and changes">
          <p>
            We may release updates to the Software through Sparkle or other mechanisms. Updates may
            add, remove, or change behaviour. We may modify these Terms at any time by publishing a
            revised version on the website; the &quot;Last updated&quot; date above identifies the
            current version. Continued use of the Site or our related services after that
            publication constitutes acceptance of the revised Terms. Your continued use of
            open-source code remains governed by its applicable licence.
          </p>
        </Section>

        <Section title="13. Termination">
          <p>
            You may stop using the Software at any time by uninstalling it. We may discontinue the
            Software, suspend distribution, or terminate availability of any feature at any time and
            for any reason, without notice or liability. Sections 3, 4, 5, 7, 8, 10, 14, and 15
            survive any termination.
          </p>
        </Section>

        <Section title="14. Governing law and exclusive jurisdiction">
          <p>
            These Terms are governed by, and shall be construed in accordance with, the substantive
            laws of Switzerland, to the exclusion of its conflict-of-laws rules and to the exclusion
            of the United Nations Convention on Contracts for the International Sale of Goods
            (CISG).
          </p>
          <p className="mt-3 font-semibold">
            Any dispute, controversy, or claim arising out of, related to, or in connection with
            these Terms, the Site, our related services, or any matter governed by these Terms —
            including disputes regarding their existence, validity, breach, termination, or
            non-contractual obligations connected to them — shall be subject to the exclusive
            jurisdiction of the ordinary courts of the Canton of Zug, Switzerland.
          </p>
          <p className="mt-3 text-sm">
            To the extent that mandatorily-applicable consumer-protection law of your habitual
            residence affords you the non-waivable right to bring suit before the courts of that
            jurisdiction, that right is preserved. Nothing in this clause prevents us from seeking
            injunctive, declaratory, or other equitable relief before any court of competent
            jurisdiction in respect of a threatened or actual infringement of intellectual property
            rights, breach of confidentiality, or misuse of the Site or our services.
          </p>
        </Section>

        <Section title="15. Severability and entire agreement">
          <p>
            If any provision of these Terms is found unenforceable, the remaining provisions shall
            continue in full force, and the unenforceable provision shall be construed to give
            effect to its intent to the fullest extent permitted by law. These Terms, together with
            the Privacy Notice, constitute the entire agreement between you and us regarding the
            Site and related services, and supersede prior or contemporaneous communications on that
            subject. Open-source licences separately govern the code and components to which they
            apply.
          </p>
        </Section>

        <Section title="16. Contact">
          <p>
            Superstellar GmbH (English: Superstellar LLC)
            <br />
            Baarerstrasse 52
            <br />
            6300 Zug, Switzerland
            <br />
            UID CHE-433.879.620
            <br />
            Email:{" "}
            <a href="mailto:apps@superstellar.io" className="text-bouclier hover:underline">
              apps@superstellar.io
            </a>
          </p>
          <p className="mt-3 text-sm">
            If anything in these Terms is unclear, contact us before using the Site or related
            services. Using open-source code within the rights granted by its applicable licence
            does not by itself constitute acceptance of separate Site terms.
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
            <Link href="/privacy" className="hover:text-text transition-colors">
              Privacy
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
