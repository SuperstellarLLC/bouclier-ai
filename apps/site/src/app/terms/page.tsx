import type { Metadata } from "next";
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
            <Link href="/privacy" className="hover:text-text transition-colors">
              Privacy
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-3xl font-bold tracking-tight">Terms of Use</h1>
        <p className="text-text-secondary mt-2 text-sm">Last updated: May 2026</p>

        {/* Loud prototype banner — anyone evaluating the software must see this first. */}
        <div className="mt-10 rounded-xl border-2 border-amber-300 bg-amber-50 p-6">
          <p className="font-semibold text-amber-900">
            Bouclier.ai is experimental, prototype software.
          </p>
          <p className="mt-2 text-sm text-amber-900">
            It is provided for evaluation, research, and personal experimentation. It is{" "}
            <strong>not</strong> intended for production use, regulated workloads, safety-critical
            systems, healthcare, financial services compliance, or any environment in which a
            detection failure could cause harm, financial loss, regulatory non-compliance, or other
            material damage. Detection is best-effort and probabilistic; false negatives and false
            positives will occur. Use at your own risk.
          </p>
        </div>

        <Section title="1. Acceptance">
          <p>
            By downloading, installing, or running Bouclier.ai (the &quot;Software&quot;), you agree
            to these Terms of Use. If you do not agree, do not install or use the Software. These
            terms apply to all components of the Software including the macOS application, the
            bundled MCP wrapper, the local proxy, the regex patterns, the on-device classifiers, the
            marketing website at bouclier.ai, and any related artifacts.
          </p>
        </Section>

        <Section title="2. Experimental status">
          <p>
            The Software is in active development and labelled as a pre-1.0 release. Version numbers
            below 1.0 indicate that the Software is a prototype: APIs, detection behaviour, file
            formats, default settings, and the set of detected entities may change without notice
            between releases. Features described in the marketing site, documentation, README, or
            in-app text may be removed, altered, or replaced at any time. You should not rely on any
            specific behaviour persisting across releases.
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
              injections and some PII. Novel attack patterns, unusual encodings, multimodal inputs
              (images, audio, files), and content the Software does not inspect will pass through
              unchanged.
            </li>
            <li>
              <strong>False positives.</strong> The Software may classify benign content as a threat
              or as PII, redact it, and disrupt the user&apos;s intended workflow.
            </li>
            <li>
              <strong>Content the Software does not inspect.</strong> Traffic to providers not on
              the intercepted-hosts list, traffic over non-HTTPS protocols, file uploads, multipart
              bodies, binary payloads, and content delivered through channels outside the macOS
              network proxy are not inspected.
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
              You are solely responsible for reviewing the redactions performed by the Software
              before relying on them. The preview modal is provided as an aid, not as a
              certification.
            </li>
            <li>
              You are solely responsible for evaluating whether the Software is appropriate for your
              environment, your data, and your obligations. You must not deploy the Software in any
              environment in which a detection failure could cause harm.
            </li>
            <li>
              You are solely responsible for the configuration of allow- and deny-domain lists,
              per-entity policies, and any MDM-managed settings. Misconfiguration can cause PII to
              be transmitted to upstream providers without redaction.
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
            The Software is designed to process all prompt content locally on your device. We do not
            operate servers that receive prompt content, redaction events, audit logs, or user
            telemetry. The only outbound network calls initiated by the Software are described in
            the{" "}
            <Link href="/privacy" className="text-bouclier hover:underline">
              Privacy Policy
            </Link>
            . You acknowledge that we therefore have no ability to recover, restore, or audit
            content processed by the Software on your behalf.
          </p>
        </Section>

        <Section title="10. Third-party providers">
          <p>
            The Software intercepts traffic to third-party AI providers and forwards modified
            content to them. We have no control over those providers, their terms, their data
            handling, their availability, or their pricing. Your use of those providers is governed
            by your agreement with each of them. The Software may rewrite the bodies of requests
            sent to those providers; the content received by the provider is what we deliver after
            redaction, and that content is what they may store and process according to their own
            terms.
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

        <Section title="14. Governing law">
          <p>
            These Terms are governed by the laws of France, without regard to its conflict-of-laws
            provisions. The courts of Paris, France shall have exclusive jurisdiction over any
            dispute arising out of or relating to these Terms or the Software, except that we may
            seek injunctive or other equitable relief in any court of competent jurisdiction.
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
