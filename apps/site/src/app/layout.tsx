import type { Metadata, Viewport } from "next";

import { APP_NAME, APP_URL } from "@/lib/constants";

import "./globals.css";

const DESCRIPTION =
  "A prompt-injection firewall for your AI coding agent. Local-only macOS app — inspects every tool result for instructions trying to reprogram your agent, on-device. No certificate required. Experimental beta — not for production.";

export const metadata: Metadata = {
  title: {
    default: `${APP_NAME} (Beta) — A prompt-injection firewall for your AI agent`,
    template: `%s | ${APP_NAME} (Beta)`,
  },
  description: DESCRIPTION,
  metadataBase: new URL(APP_URL),
  openGraph: {
    title: `${APP_NAME} (Beta) — A prompt-injection firewall for your AI agent`,
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
