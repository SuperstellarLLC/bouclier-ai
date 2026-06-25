import type { Metadata, Viewport } from "next";

import { APP_NAME, APP_URL } from "@/lib/constants";

import "./globals.css";

const DESCRIPTION =
  "Let your AI coding agent use your secrets without ever seeing them. Local-only macOS app — keeps API keys out of the model, blocks prompt injection, strips PII. Experimental beta — not for production.";

export const metadata: Metadata = {
  title: {
    default: `${APP_NAME} (Beta) — Your AI agent uses your secrets, never sees them`,
    template: `%s | ${APP_NAME} (Beta)`,
  },
  description: DESCRIPTION,
  metadataBase: new URL(APP_URL),
  openGraph: {
    title: `${APP_NAME} (Beta) — Your AI agent uses your secrets, never sees them`,
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
  themeColor: "#ffffff",
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
      <body className="text-text bg-white antialiased">{children}</body>
    </html>
  );
}
