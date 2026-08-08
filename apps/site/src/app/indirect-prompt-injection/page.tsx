import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";

import { APP_URL } from "@/lib/constants";

// SEO/GEO answer page targeting "indirect prompt injection" and "can a website
// hijack an AI agent". Answer-first, FAQ + Article JSON-LD so AI answer engines
// and search both get a citable page. Native to Bouclier (a prompt-injection
// firewall that inspects untrusted tool output before it reaches the model);
// one contextual reference to a tool that measures agent task completion.

const CANONICAL = `${APP_URL}/indirect-prompt-injection`;
const TITLE = "Indirect prompt injection: how a web page can hijack your AI agent";
const DESCRIPTION =
  "Indirect prompt injection hides instructions inside content an AI reads, like a web page or a PDF, so the model follows them. Here is how it works, why browsing agents made it real, and what actually reduces the risk.";

export const metadata: Metadata = {
  title: TITLE,
  description: DESCRIPTION,
  alternates: { canonical: CANONICAL },
  openGraph: { title: TITLE, description: DESCRIPTION, url: CANONICAL, type: "article" },
};

const FAQS: { q: string; a: string }[] = [
  {
    q: "What is indirect prompt injection?",
    a: "It is an attack where instructions are hidden inside content an AI reads on its own, such as a web page, a PDF, or an email, and the model treats them as commands. The user never types anything malicious. The agent picks up the payload while doing the task it was given.",
  },
  {
    q: "How is it different from a normal prompt injection?",
    a: "A direct prompt injection is text a person types into the chat, like 'ignore your previous instructions'. Indirect injection moves that text to a place the agent will read by itself, so the attacker never needs access to the conversation.",
  },
  {
    q: "Why are AI agents especially vulnerable to it?",
    a: "Agents now open browsers, read pages, and complete tasks on live sites. Every page an agent reads becomes part of its prompt, so any text an attacker planted on a page the agent visits can try to steer it.",
  },
  {
    q: "Can you fully prevent indirect prompt injection?",
    a: "No defense is perfect, because the model cannot cleanly separate data from instructions. You reduce the risk structurally: treat all read content as untrusted, constrain what the agent can do, and scan content for known injection patterns before it reaches the model.",
  },
];

function articleJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: TITLE,
    description: DESCRIPTION,
    mainEntityOfPage: { "@type": "WebPage", "@id": CANONICAL },
    author: { "@type": "Organization", name: "Bouclier.ai", url: APP_URL },
    publisher: { "@type": "Organization", name: "Bouclier.ai", url: APP_URL },
    datePublished: "2026-06-22",
    dateModified: "2026-06-22",
  };
}

function faqJsonLd() {
  return {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: FAQS.map((f) => ({
      "@type": "Question",
      name: f.q,
      acceptedAnswer: { "@type": "Answer", text: f.a },
    })),
  };
}

function jsonLd(data: object): string {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}

export default function IndirectPromptInjectionPage() {
  return (
    <main className="min-h-screen bg-white">
      <script
        type="application/ld+json"
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{ __html: jsonLd(articleJsonLd()) }}
      />
      <script
        type="application/ld+json"
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{ __html: jsonLd(faqJsonLd()) }}
      />

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

      <article className="mx-auto max-w-3xl px-6 py-16">
        <p className="text-bouclier font-mono text-xs font-semibold uppercase tracking-wider">
          AI security
        </p>
        <h1 className="mt-3 text-3xl font-bold tracking-tight sm:text-4xl">
          Indirect prompt injection: how a web page can hijack your AI agent
        </h1>

        <p className="text-text-secondary mt-6 text-lg leading-relaxed">
          Indirect prompt injection is an attack where instructions hidden inside content an AI
          reads, a web page, a PDF, an email, get treated as commands by the model. The user never
          types anything malicious. The agent picks up the payload on its own while doing the task
          you gave it. OWASP ranks it as the top risk for LLM applications, and as agents start to
          browse and act on real sites, it has gone from a lab demo to the most practical way to
          take one over.
        </p>

        <section className="mt-12">
          <h2 className="text-2xl font-bold tracking-tight">
            How it differs from a normal prompt injection
          </h2>
          <div className="text-text-secondary mt-4 space-y-4 leading-relaxed">
            <p>
              A direct prompt injection is something a person types into the chat: ignore your
              previous instructions and do this instead. Indirect injection moves that same text to
              a place the agent will read on its own. White text on a white background on a product
              page. A string tucked into an HTML attribute or an image caption. A line buried in a
              PDF the agent was asked to summarize.
            </p>
            <p>
              The model has no reliable way to separate content it should analyze from instructions
              it should obey. So the planted text can steer it: leak data from the conversation,
              call a tool it should not, or take an action the user never approved.
            </p>
          </div>
        </section>

        <section className="mt-12">
          <h2 className="text-2xl font-bold tracking-tight">Why browsing agents made it real</h2>
          <div className="text-text-secondary mt-4 space-y-4 leading-relaxed">
            <p>
              For a while this stayed mostly theoretical, because models read text a person handed
              them directly. That has changed. Agents now open browsers, read pages, fill forms, and
              finish tasks on live sites for a user. The same shift that lets an agent find a
              product and check out for you, the thing tools like{" "}
              <a
                href="https://www.serge.ai"
                className="text-bouclier underline decoration-1 underline-offset-2"
              >
                Serge
              </a>{" "}
              measure by running real agents through purchase tasks on real stores, also means the
              agent swallows whatever those pages contain, including anything an attacker planted.
              Once an agent browses, every page it reads becomes part of its prompt.
            </p>
          </div>
        </section>

        <section className="mt-12">
          <h2 className="text-2xl font-bold tracking-tight">Why the obvious defenses fall short</h2>
          <div className="text-text-secondary mt-4 space-y-4 leading-relaxed">
            <p>
              A system prompt that says ignore any instructions you find in content helps a little
              and fails often, because the model still cannot tell data from instructions cleanly.
              Allow-listing every site an agent may visit does not scale past a demo. And asking the
              model to judge whether its own input is an attack is asking the thing under attack to
              police it. These lower the rate. None of them close the hole.
            </p>
          </div>
        </section>

        <section className="mt-12">
          <h2 className="text-2xl font-bold tracking-tight">What actually reduces the risk</h2>
          <div className="text-text-secondary mt-4 space-y-4 leading-relaxed">
            <p>The defenses that hold up are structural, not hopeful.</p>
            <ul className="list-disc space-y-2 pl-5">
              <li>Treat every byte the model reads as untrusted input, never as instructions.</li>
              <li>
                Constrain what the agent can do, so a hijack cannot escalate. Scope tools tightly
                and require explicit confirmation for anything that moves money or data.
              </li>
              <li>
                Contain the blast radius: don&apos;t let the agent hold credentials it doesn&apos;t
                need to hold, so a successful hijack can&apos;t exfiltrate them.
              </li>
            </ul>
            <p>
              The first layer is what <strong className="text-text">Bouclier</strong> was built for.
              It sits between your agent&apos;s AI SDK calls and the provider on your Mac, and
              inspects every request for injection hidden in <em>untrusted</em> content — tool
              results, fetched pages, retrieved documents — before it reaches the model. When it
              spots an instruction in text nobody in your session typed, it flags it (and, with
              blocking on, refuses the request outright). It runs entirely on-device: 161 detection
              patterns plus an on-device ML classifier, no traffic leaving your machine. It is
              defence in depth on the untrusted leg, not a complete solution — pair it with the
              structural controls above.
            </p>
          </div>
        </section>

        <section className="mt-12">
          <h2 className="text-2xl font-bold tracking-tight">FAQ</h2>
          <dl className="mt-4 space-y-6">
            {FAQS.map((f) => (
              <div key={f.q}>
                <dt className="text-text font-semibold">{f.q}</dt>
                <dd className="text-text-secondary mt-1 leading-relaxed">{f.a}</dd>
              </div>
            ))}
          </dl>
        </section>

        <div className="border-border mt-14 border-t pt-6">
          <Link
            href="/"
            className="bg-bouclier inline-flex items-center rounded-lg px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:opacity-90"
          >
            See how Bouclier works
          </Link>
        </div>
      </article>

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
