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
            Ilvarion processes all data locally on your device. We do not collect personal data. We
            do not operate servers that receive your data. We have no analytics, no telemetry, and
            no user accounts.
          </Text>
        </Box>

        <Heading level={3}>What Ilvarion does</Heading>
        <Text color="secondary">
          Ilvarion is a local network proxy that scans AI API traffic for prompt injection attacks.
          It intercepts HTTPS connections to a specific set of AI API domains (listed below),
          decrypts them using a locally-generated certificate authority, inspects the request
          content for injection patterns, and forwards the request to the intended destination.
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
          Organizations using MDM can add additional domains via managed app configuration.
        </Text>

        <Heading level={3}>Network connections made by Ilvarion</Heading>
        <Text color="secondary">
          Ilvarion makes the following network connections. There are no other outbound connections.
        </Text>
        <Text color="secondary">
          1. Forwarding your AI API requests to their intended destination (the core function of the
          proxy). Request content may be modified if a prompt injection is detected.
        </Text>
        <Text color="secondary">
          2. Checking for software updates via an appcast.xml file hosted on ilvarion.com. This
          check transmits the current app version, macOS version, CPU architecture, and preferred
          language. No personal data, API keys, or request content is included.
        </Text>
        <Text color="secondary">
          3. If and only if an organization&apos;s IT administrator has configured a SIEM webhook
          URL via MDM (managed app configuration), scan event metadata (timestamp, target host,
          pattern matched, severity) is sent to that organization-controlled endpoint. This is never
          enabled by default and cannot be configured by the user — only by MDM.
        </Text>

        <Heading level={3}>Data stored locally</Heading>
        <Text color="secondary">
          The following data is stored on your device at ~/Library/Application
          Support/com.ilvarion.Ilvarion/:
        </Text>
        <Text color="secondary">
          - Scan logs: timestamp, source (api-proxy or mcp-proxy), target host, whether an injection
          was detected, match count, matched pattern IDs, severity, and request size in bytes. No
          request body content is stored. Logs are automatically deleted after 30 days.
        </Text>
        <Text color="secondary">
          - Daily aggregate statistics: date, total requests scanned, total injections blocked.
          Retained for 365 days.
        </Text>
        <Text color="secondary">
          - CA certificate (public): stored as a PEM file. This is not sensitive.
        </Text>
        <Text color="secondary">
          - CA private key: stored in the macOS Keychain (encrypted at rest), protected by
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly. The private key is never written to disk in
          plaintext after initial generation.
        </Text>
        <Text color="secondary">
          - User preferences: proxy port, notification settings, launch-at-login preference. Stored
          via macOS UserDefaults.
        </Text>

        <Heading level={3}>Data we collect</Heading>
        <Text color="secondary">
          We do not collect personal data. Ilvarion has no user accounts, no analytics, no crash
          reporting, and no usage telemetry. The only network connections Ilvarion initiates are
          those listed in the &quot;Network connections&quot; section above.
        </Text>

        <Heading level={3}>Data we share</Heading>
        <Text color="secondary">
          We do not share data. The SIEM webhook feature (enterprise only, MDM-configured) sends
          scan event metadata to infrastructure controlled by the organization&apos;s IT
          administrator, not to Ilvarion or any third party.
        </Text>

        <Heading level={3}>Detection method</Heading>
        <Text color="secondary">
          Ilvarion uses deterministic regex pattern matching and heuristic scoring to detect prompt
          injections. No AI or machine learning model is used for detection. No request content is
          sent to any external service for analysis.
        </Text>

        <Heading level={3}>Certificate authority</Heading>
        <Text color="secondary">
          Ilvarion generates a local root CA certificate on your device during setup. This
          certificate is used solely to decrypt AI API traffic for inspection. The private key never
          leaves your device. You can remove the CA at any time via the app&apos;s settings, which
          also removes it from the macOS trust store.
        </Text>

        <Heading level={3}>Open source</Heading>
        <Text color="secondary">
          Ilvarion is open source. You can audit every line of code, every detection pattern, and
          every network call at github.com/Ilvarion/ilvarion.
        </Text>

        <Heading level={3}>Contact</Heading>
        <Text color="secondary">Privacy questions: privacy@ilvarion.com</Text>
        <Text color="secondary">Support: support@ilvarion.com</Text>
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
