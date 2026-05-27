import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Terms of Use",
};

export default function TermsPage() {
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
            <Link href="/privacy" className="hover:text-text transition-colors">
              Privacy
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-3xl font-bold tracking-tight">Terms of Use</h1>
        <p className="text-text-secondary mt-2 text-sm">Last updated: 27 May 2026</p>

        {/* Loud prototype banner — anyone evaluating the software must see this first. */}
        <div className="mt-10 rounded-xl border-2 border-amber-300 bg-amber-50 p-6">
          <p className="font-semibold text-amber-900">
            Bouclier.ai is a research prototype. It is not a commercial product.
          </p>
          <p className="mt-2 text-sm text-amber-900">
            The Software is published for evaluation, security research, academic study, and
            personal experimentation only. It is <strong>not</strong> a commercial product, is{" "}
            <strong>not</strong> sold, distributed, or offered for production use, and is{" "}
            <strong>not</strong> intended for regulated workloads, safety-critical systems,
            healthcare, financial services, payment processing, identity verification, fraud
            prevention, or any environment in which a detection failure could cause harm, financial
            loss, regulatory non-compliance, or other material damage. Detection is best-effort and
            probabilistic; false negatives and false positives will occur. You may not deploy the
            Software as a security control on which any other person or system relies. Use at your
            own risk and at your own cost.
          </p>
        </div>

        <Section title="1. Acceptance">
          <p>
            By downloading, installing, or running Bouclier.ai (the &quot;Software&quot;), or by
            accessing the website at bouclier.ai (the &quot;Site&quot;), you agree to these Terms of
            Use. If you do not agree, do not install or use the Software, and do not access the
            Site. These terms apply to all components of the Software including the macOS
            application, the bundled MCP wrapper, the local proxy, the regex pattern library, the
            on-device classifiers, the Site, and any related artifacts, documentation, or sample
            data.
          </p>
        </Section>

        <Section title="2. Research prototype — not a commercial product">
          <p>
            The Software is a research prototype published as the output of independent security and
            machine-learning research. It is not a commercial product. We do not market, sell,
            licence for a fee, or commercially distribute the Software, make no representations
            regarding its fitness for any operational purpose, and offer no service-level agreement,
            paid support tier, professional services, uptime commitment, or commercial obligation of
            any kind.
          </p>
          <p className="mt-3">
            The Software is published under the Apache License, Version 2.0; you are welcome to
            read, audit, modify, fork, and rebuild the source. The project&apos;s intent is research
            output — independent security testing, academic engagement, and contributor feedback are
            welcome. Deployment of the Software in any environment where its failure would cause
            loss, harm, regulatory consequence, or third-party reliance is expressly outside the
            project&apos;s intended use and is undertaken solely at the deploying party&apos;s risk.
          </p>
          <p className="mt-3">
            Pre-1.0 version numbering reflects this status. APIs, detection behaviour, file formats,
            default settings, the set of detected entities, the rewriter behaviour, and the scope of
            intercepted traffic may change without notice between releases. Features described in
            marketing materials, documentation, the README, the changelog, or in-app text may be
            removed, altered, or replaced at any time. You must not rely on any specific behaviour
            persisting across releases.
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
            Without limiting the foregoing, we make no warranty that the Software will detect any
            specific class of prompt injection, redact any specific category of personal
            information, preserve any specific behaviour across sessions or releases, be free of
            errors, operate without interruption, be secure against any specific threat,
            interoperate with any third-party tool or service, or meet any regulatory or compliance
            requirement.
          </p>
        </Section>

        <Section title="4. Detection is best-effort and probabilistic">
          <p>
            The Software performs regex pattern matching, structural validation, statistical
            heuristics, and on-device machine learning to identify likely prompt injections and
            likely PII. None of these techniques is exhaustive. Specifically and without limitation:
          </p>
          <ul className="mt-3 list-disc space-y-2 pl-5">
            <li>
              <strong>False negatives.</strong> The Software will fail to detect some prompt
              injections and some PII. Novel attack patterns, unusual encodings, low-resolution or
              heavily-stylised images, scanned PDFs with poor OCR quality, accented or low-quality
              audio, and content the Software does not inspect will pass through unchanged.
            </li>
            <li>
              <strong>False positives.</strong> The Software may classify benign content as a threat
              or as PII, redact it, strip an attachment, and disrupt the user&apos;s intended
              workflow.
            </li>
            <li>
              <strong>Multimodal scope.</strong> When enabled, image OCR + face detection, PDF text
              extraction + OCR fallback, and audio transcription (capped at 60 seconds, on-device
              Apple Speech) run on attachments in JSON and multipart bodies. Video, encrypted or
              password-protected PDFs, oversized files, unsupported audio formats, and any
              attachment delivered through a channel outside the intercepted HTTPS traffic are not
              inspected. Unscannable attachments inside a flagged request may be stripped rather
              than forwarded.
            </li>
            <li>
              <strong>Content the Software does not inspect.</strong> Traffic to providers not on
              the intercepted-hosts list, traffic over non-HTTPS protocols, binary payloads outside
              the recognised multimodal shapes, and content delivered through channels outside the
              macOS network proxy are not inspected.
            </li>
            <li>
              <strong>Coverage of regulated identifiers.</strong> The Software detects a small
              subset of personal data categories defined by laws such as the EU GDPR, US HIPAA, UK
              Data Protection Act, and the California CCPA. It is not a substitute for a data
              protection impact assessment, a Business Associate Agreement, a SOC 2 control
              framework, or any other compliance instrument.
            </li>
          </ul>
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
              You are solely responsible for reviewing any rewrites performed by the Software —
              today limited to attachment content blocks flagged as containing PII — before relying
              on the result. The exported audit report is provided as an evaluation aid, not as a
              certification.
            </li>
            <li>
              You are solely responsible for evaluating whether the Software is appropriate for your
              environment, your data, and your obligations. You must not deploy the Software in any
              environment in which a detection failure could cause harm to you, to your employer, to
              your customers, or to any third party.
            </li>
            <li>
              You are solely responsible for the configuration of every Software setting, including
              MDM-managed values. Misconfiguration may cause attachments containing PII to be
              transmitted to upstream providers without inspection, or conversely may cause benign
              attachments to be stripped from outbound requests.
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
            TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL BOUCLIER.AI, ITS
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
            BOUCLIER.AI FOR THE SOFTWARE IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE
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
            You agree to indemnify, defend, and hold harmless Bouclier.ai, its contributors, agents,
            affiliates, and licensors from and against any and all claims, damages, obligations,
            losses, liabilities, costs, debts, and expenses (including but not limited to legal
            fees) arising from your use of, or inability to use, the Software; your violation of
            these Terms; your violation of any third-party right, including without limitation any
            copyright, property, privacy, or data-protection right; or your violation of any law,
            rule, or regulation.
          </p>
        </Section>

        <Section title="9. Local-only processing; no data collection">
          <p>
            The Software is designed to process all prompt content, attachment content, and
            detection signals locally on your device. We do not operate servers that receive prompt
            content, attachment content, audit logs, or user telemetry. The only outbound network
            calls initiated by the Software are described in the{" "}
            <Link href="/privacy" className="text-bouclier hover:underline">
              Privacy Policy
            </Link>
            . You acknowledge that we therefore have no ability to recover, restore, undo, or audit
            content processed by the Software on your behalf, and that we cannot intervene in any
            interaction between the Software, your computer, and the third-party AI providers you
            send traffic to.
          </p>
        </Section>

        <Section title="10. Third-party providers">
          <p>
            The Software intercepts traffic to third-party AI providers and forwards it to them.
            Text prompt bodies and HTTP request headers are forwarded byte-for-byte; the only
            content the Software ever modifies on an outbound request is an attachment (image, PDF,
            or audio file) that the on-device scanner has flagged as containing personal data, in
            which case the attachment&apos;s content block is replaced with a short text
            description. We have no control over those providers, their terms, their data handling,
            their availability, or their pricing. Your use of those providers is governed by your
            agreement with each of them. Content delivered to each provider is governed by that
            provider&apos;s own terms.
          </p>
        </Section>

        <Section title="11. Open-source components">
          <p>
            The Software incorporates open-source components, including (without limitation)
            Meta&apos;s Llama Prompt Guard 2 (governed by the Llama 4 Community License), Microsoft
            Presidio recognition patterns derived from public references, and the Swift, NIO, GRDB,
            and CryptoKit ecosystems. The corresponding notices are bundled with the Software and
            reproduced in the project&apos;s LICENSE and NOTICE files. These components remain
            governed by their respective licences.
          </p>
        </Section>

        <Section title="12. Updates and changes">
          <p>
            We may release updates to the Software through Sparkle or other mechanisms. Updates may
            add, remove, or change behaviour. Continued use of the Software after an update
            constitutes acceptance of the updated Software and these Terms. We may modify these
            Terms at any time by publishing a revised version on the website; the &quot;Last
            updated&quot; date above identifies the current version.
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
            these Terms, the Software, the Site, or any matter governed by these Terms — including
            disputes regarding their existence, validity, breach, termination, or non-contractual
            obligations connected to them — shall be subject to the exclusive jurisdiction of the
            ordinary courts of the Canton of Zug, Switzerland.
          </p>
          <p className="mt-3 text-sm">
            To the extent that mandatorily-applicable consumer-protection law of your habitual
            residence affords you the non-waivable right to bring suit before the courts of that
            jurisdiction, that right is preserved. Nothing in this clause prevents us from seeking
            injunctive, declaratory, or other equitable relief before any court of competent
            jurisdiction in respect of a threatened or actual infringement of intellectual property
            rights, breach of confidentiality, or unauthorised use of the Software.
          </p>
        </Section>

        <Section title="15. Severability and entire agreement">
          <p>
            If any provision of these Terms is found unenforceable, the remaining provisions shall
            continue in full force, and the unenforceable provision shall be construed to give
            effect to its intent to the fullest extent permitted by law. These Terms, together with
            the Privacy Policy and any licences accompanying open-source components, constitute the
            entire agreement between you and us with respect to the Software, and supersede any
            prior or contemporaneous communications.
          </p>
        </Section>

        <Section title="16. Contact">
          <p>Legal: legal@bouclier.ai</p>
          <p>Support: support@bouclier.ai</p>
          <p className="mt-3 text-sm">
            If anything in these Terms is unclear, contact us before you install or use the
            Software. We will not interpret your continued use as acceptance of any clause you have
            raised in good faith for clarification.
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
