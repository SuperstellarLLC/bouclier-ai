import type { Metadata } from "next";
import { Page, Stack, Heading, Text, Box, Divider, Nav, Footer } from "@n3rd-ai/ui";

export const metadata: Metadata = {
  title: "Privacy Policy",
};

export default function PrivacyPage() {
  return (
    <Page>
      <Nav
        items={[
          { label: "HOME", href: "/" },
          { label: "PRIVACY", href: "/privacy", active: true },
          { label: "GITHUB", href: "https://github.com/Ilvarion/ilvarion", external: true },
        ]}
      />

      <Stack gap="lg" style={{ paddingTop: "3rem", paddingBottom: "2rem" }}>
        <Heading level={1}>Privacy Policy</Heading>
        <Text color="secondary">Last updated: April 2026</Text>
      </Stack>

      <Divider />

      <Stack gap="lg" style={{ paddingTop: "2rem", paddingBottom: "2rem" }}>
        <Heading level={3}>Summary</Heading>
        <Box border="double" accent="success" padding="lg">
          <Text>
            Ilvarion processes all data locally on your device. We collect nothing. We transmit
            nothing. We have no servers, no analytics, no telemetry, and no user accounts.
          </Text>
        </Box>

        <Heading level={3}>What Ilvarion does</Heading>
        <Text color="secondary">
          Ilvarion is a local network proxy that scans AI API traffic for prompt injection attacks.
          It intercepts HTTPS connections to a specific set of AI API domains (listed below),
          decrypts them using a locally-generated certificate authority, inspects the request
          content for injection patterns, and forwards the (potentially sanitized) request to the
          intended destination.
        </Text>

        <Heading level={3}>Intercepted domains</Heading>
        <Text color="secondary">
          Ilvarion only intercepts traffic to these specific domains. All other network traffic is
          completely untouched and never passes through Ilvarion:
        </Text>
        <Box border="single" padding="md">
          <Text size="sm">
            api.openai.com, api.anthropic.com, api.cohere.com, api.mistral.ai,
            generativelanguage.googleapis.com, api.together.xyz, api.groq.com, api.perplexity.ai,
            api.fireworks.ai, openrouter.ai
          </Text>
        </Box>
        <Text color="secondary">
          Organizations using MDM can add additional domains to this list.
        </Text>

        <Heading level={3}>Data processing</Heading>
        <Text color="secondary">All inspection happens locally on your Mac. Specifically:</Text>
        <Text color="secondary">
          - Request bodies are scanned using deterministic regex patterns (no AI/ML model is used
          for detection)
        </Text>
        <Text color="secondary">
          - Scan results (blocked/allowed, pattern matched, target host, timestamp) are stored in a
          local SQLite database at ~/Library/Application Support/dev.ilvarion.Ilvarion/
        </Text>
        <Text color="secondary">- Logs are automatically deleted after 30 days</Text>
        <Text color="secondary">
          - The CA private key is stored in your macOS Keychain, encrypted at rest
        </Text>

        <Heading level={3}>Data we collect</Heading>
        <Text color="secondary">
          None. Zero. Ilvarion has no network calls of its own (except forwarding your AI API
          requests to their intended destination). There is no analytics, no crash reporting, no
          usage telemetry, no phone-home, and no user accounts.
        </Text>

        <Heading level={3}>Data we share</Heading>
        <Text color="secondary">None. There is nothing to share because we collect nothing.</Text>

        <Heading level={3}>Enterprise (SIEM webhook)</Heading>
        <Text color="secondary">
          Organizations can optionally configure a webhook URL (via MDM) to forward scan event logs
          to their own SIEM system. This is explicitly configured by the organization's IT
          administrator and sends data only to infrastructure the organization controls. Ilvarion
          itself never receives this data.
        </Text>

        <Heading level={3}>Automatic updates</Heading>
        <Text color="secondary">
          Ilvarion checks for updates via an appcast.xml file hosted on ilvarion.dev. This check
          transmits only the current app version. Updates are verified using EdDSA signatures and
          must pass Apple notarization. No personal data is included in update checks.
        </Text>

        <Heading level={3}>Certificate authority</Heading>
        <Text color="secondary">
          Ilvarion generates a local root CA certificate on your device during setup. This
          certificate is used solely to decrypt AI API traffic for inspection. The private key never
          leaves your device and is stored in the macOS Keychain. You can remove the CA at any time
          via the app's settings.
        </Text>

        <Heading level={3}>Contact</Heading>
        <Text color="secondary">For privacy questions: privacy@ilvarion.dev</Text>
        <Text color="secondary">For support: support@ilvarion.dev</Text>
      </Stack>

      <Divider />

      <Footer
        tagline="Local prompt injection firewall"
        links={[
          { label: "Home", href: "/" },
          { label: "GitHub", href: "https://github.com/Ilvarion/ilvarion", external: true },
        ]}
      />
    </Page>
  );
}
