import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Sets a strict Content-Security-Policy and the standard security headers on
 * every non-static response.
 *
 * Rate limiting is intentionally NOT done here. The previous in-app limiter
 * keyed on the client-spoofable leftmost `X-Forwarded-For` and lived in
 * per-instance memory with no global ceiling — ineffective by construction
 * (see the security review), and it made the app read a client IP at all.
 * Abuse mitigation for the one public write endpoint (`/api/report`) is now a
 * proof-of-work stamp plus a global per-minute write cap in the app, with
 * per-IP rate limiting pushed to the edge (Vercel Firewall) where an IP is
 * transport, not data we collect. This middleware reads no IP, cookie, or
 * identifier.
 */
export function middleware(request: NextRequest) {
  // Next.js injects inline scripts for hydration that can't use nonces in RSC
  // mode, so 'unsafe-inline' is required. 'unsafe-eval' is only needed by the
  // dev server (HMR / React Refresh), so it's excluded from production — the
  // deployed CSP has no eval escape hatch. Fonts loaded from Google Fonts.
  const scriptSrc =
    process.env.NODE_ENV === "development"
      ? `script-src 'self' 'unsafe-inline' 'unsafe-eval'`
      : `script-src 'self' 'unsafe-inline'`;
  const cspDirectives = [
    `default-src 'self'`,
    scriptSrc,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self' https://fonts.gstatic.com`,
    `connect-src 'self'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `object-src 'none'`,
  ];

  const response = NextResponse.next({
    request: {
      headers: new Headers(request.headers),
    },
  });

  response.headers.set("Content-Security-Policy", cspDirectives.join("; "));
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  );
  response.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization)
     * - favicon.ico (favicon)
     * - public folder assets
     */
    "/((?!_next/static|_next/image|favicon.ico|images/).*)",
  ],
};
