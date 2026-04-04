import type { Metadata, Viewport } from "next";
import { N3rdProvider } from "@n3rd-ai/ui";
import "@n3rd-ai/ui/theme/classic.css";
import "@n3rd-ai/ui/theme/fonts.css";

import { APP_NAME, APP_URL } from "@/lib/constants";

import "./globals.css";

const DESCRIPTION =
  "Local prompt injection firewall for macOS. Scans AI API traffic and MCP tool results. No data leaves your machine.";

export const metadata: Metadata = {
  title: {
    default: `${APP_NAME} — Prompt Injection Firewall`,
    template: `%s | ${APP_NAME}`,
  },
  description: DESCRIPTION,
  metadataBase: new URL(APP_URL),
  openGraph: {
    title: `${APP_NAME} — Prompt Injection Firewall`,
    description: DESCRIPTION,
    siteName: APP_NAME,
    locale: "en_US",
    type: "website",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export const viewport: Viewport = {
  themeColor: "#0a0a0a",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <N3rdProvider>{children}</N3rdProvider>
      </body>
    </html>
  );
}
