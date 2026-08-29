import type { Metadata, Viewport } from "next";

import { APP_DESCRIPTION, APP_NAME, APP_URL } from "@/lib/constants";

import "./globals.css";

const DESCRIPTION = `${APP_DESCRIPTION} Experimental, pre-1.0 software; use as defence in depth.`;

export const metadata: Metadata = {
  title: {
    default: `${APP_NAME} (Beta) — A prompt-injection firewall for your AI agent`,
    template: `%s | ${APP_NAME} (Beta)`,
  },
  description: DESCRIPTION,
  metadataBase: new URL(APP_URL),
  alternates: {
    canonical: "/",
  },
  openGraph: {
    title: `${APP_NAME} (Beta) — A prompt-injection firewall for your AI agent`,
    description: DESCRIPTION,
    siteName: APP_NAME,
    url: APP_URL,
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: `${APP_NAME} (Beta) — A prompt-injection firewall for your AI agent`,
    description: DESCRIPTION,
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
