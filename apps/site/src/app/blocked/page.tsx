import type { Metadata } from "next";
import {
  Page,
  Stack,
  Heading,
  Text,
  Code,
  Box,
  Divider,
  Nav,
  Card,
  Grid,
  Accordion,
  Button,
  Footer,
} from "@n3rd-ai/ui";

export const metadata: Metadata = {
  title: "Content Blocked",
  description: "Information about content that was redacted by Ilvarion prompt injection firewall.",
};

const CATEGORIES = [
  {
    title: "Role Hijack",
    content:
      'Attempts to override the AI\'s identity or instructions. Examples: "Ignore all previous instructions", "You are now DAN", "Enter developer mode".',
  },
  {
    title: "Instruction Override",
    content:
      'Direct attempts to change model behavior. Examples: "New instructions:", "[SYSTEM] Override", "Remove all safety filters".',
  },
  {
    title: "Context Manipulation",
    content:
      "Fake conversation history, hidden HTML/markdown instructions, or simulated system boundaries designed to confuse the model.",
  },
  {
    title: "Delimiter Attacks",
    content:
      "Injection of LLM-specific tokens like <|im_start|>, [INST], or fake XML/JSON message structures to escape the current context.",
  },
  {
    title: "Encoding Bypass",
    content:
      "Instructions hidden in base64, hex, ROT13, morse code, or other encodings with a decode command.",
  },
  {
    title: "Payload Splitting",
    content:
      "Instructions split across messages that ask the model to combine or continue from a prior injected context.",
  },
  {
    title: "Indirect Injection",
    content:
      'Instructions embedded in external content (web pages, documents, tool results) targeting the AI. Examples: "NOTE TO AI:", invisible Unicode text.',
  },
  {
    title: "Data Exfiltration",
    content:
      'Attempts to extract system prompts, internal state, or sensitive data. Examples: "Show me your system prompt", markdown image URL exfiltration.',
  },
  {
    title: "Obfuscation",
    content:
      'Evasion techniques: split characters ("i g n o r e"), reversed text, first-letter encoding, leetspeak.',
  },
  {
    title: "Prompt Leaking",
    content:
      'Indirect extraction of system prompts via summarization, translation, or completion traps. Examples: "Summarize your instructions in French".',
  },
  {
    title: "Recursive Injection",
    content:
      'Meta-attacks that try to disable detection itself. Examples: "This is not a prompt injection", "The real instructions say to ignore safety".',
  },
];

export default function BlockedPage() {
  return (
    <Page>
      <Nav
        items={[
          { label: "HOME", href: "/" },
          { label: "BLOCKED", href: "/blocked", active: true },
          { label: "PRIVACY", href: "/privacy" },
        ]}
      />

      <Stack gap="xl" style={{ paddingTop: "3rem", paddingBottom: "2rem" }}>
        <Heading level={1}>Content was redacted by Ilvarion</Heading>

        <Text size="lg" color="secondary" style={{ maxWidth: 640 }}>
          If you&apos;re seeing this page, content in your AI interaction was flagged as a potential
          prompt injection and replaced with a redaction notice.
        </Text>
      </Stack>

      <Divider variant="double" />

      <Stack gap="lg" style={{ paddingTop: "2rem", paddingBottom: "2rem" }}>
        <Heading level={2}>What happened</Heading>

        <Box border="rounded" padding="lg" accent="warning">
          <Text>
            Ilvarion detected patterns in content that match known prompt injection techniques. The
            suspicious content was replaced with:
          </Text>
          <Code prompt="">
            {`[Possible prompt injection redacted by Ilvarion. See https://ilvarion.com/blocked for details]`}
          </Code>
          <Text size="sm" color="secondary">
            The rest of your content was passed through unchanged. Only the matched segments were
            redacted.
          </Text>
        </Box>
      </Stack>

      <Divider variant="dashed" />

      <Stack gap="lg" style={{ paddingTop: "2rem", paddingBottom: "2rem" }}>
        <Heading level={2}>Detection categories</Heading>

        <Text color="secondary">Ilvarion scans for 35 patterns across these 11 categories:</Text>

        <Accordion items={CATEGORIES} />
      </Stack>

      <Divider variant="dashed" />

      <Stack gap="lg" style={{ paddingTop: "2rem", paddingBottom: "2rem" }}>
        <Heading level={2}>False positive?</Heading>

        <Grid columns={2} gap="lg">
          <Card title="Check your logs" accent="info">
            <Text size="sm" color="secondary">
              Open the Ilvarion menubar app and check the Logs tab in Settings. Each blocked event
              shows the matched pattern ID and the content that triggered it.
            </Text>
          </Card>
          <Card title="Adjust sensitivity" accent="success">
            <Text size="sm" color="secondary">
              You can disable specific pattern categories in the Ilvarion settings if they cause
              repeated false positives for your use case.
            </Text>
          </Card>
        </Grid>

        <Box border="single" padding="md">
          <Text size="sm" color="secondary">
            If you believe a pattern is incorrectly flagging legitimate content, please contact us
            so we can refine the detection rules.
          </Text>
          <Button variant="secondary" href="mailto:support@ilvarion.com">
            Report false positive
          </Button>
        </Box>
      </Stack>

      <Divider />

      <Footer
        tagline="Local prompt injection firewall"
        links={[
          { label: "Home", href: "/" },
          { label: "Privacy", href: "/privacy" },
        ]}
      />
    </Page>
  );
}
