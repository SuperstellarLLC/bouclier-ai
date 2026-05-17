import type { Metadata, Viewport } from "next";

import { APP_NAME, APP_URL } from "@/lib/constants";

import "./globals.css";

const DESCRIPTION =
  "Stop prompt injections. Stop PII from leaking to LLMs. Local-only macOS app. Experimental beta — not for production.";

export const metadata: Metadata = {
  title: {
    default: `${APP_NAME} (Beta) — Stop PII from leaking to LLMs`,
    template: `%s | ${APP_NAME} (Beta)`,
  },
  description: DESCRIPTION,
  metadataBase: new URL(APP_URL),
  openGraph: {
    title: `${APP_NAME} (Beta) — Stop PII from leaking to LLMs`,
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
