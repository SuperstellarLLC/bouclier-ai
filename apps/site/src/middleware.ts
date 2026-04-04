import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Rate limiting using a simple in-memory sliding window.
 * For production at scale, replace with Redis-backed rate limiting.
 */
const rateLimit = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 100; // per window

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimit.get(ip);

  if (!entry || now > entry.resetTime) {
    rateLimit.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }

  entry.count++;

  // Lazy cleanup: evict stale entries when map grows large (avoids setInterval in serverless)
  if (rateLimit.size > 10_000) {
    for (const [key, val] of rateLimit) {
      if (now > val.resetTime) rateLimit.delete(key);
    }
  }

  return entry.count > RATE_LIMIT_MAX_REQUESTS;
}

export function middleware(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

  // Rate limiting
  if (isRateLimited(ip)) {
    return new NextResponse("Too Many Requests", { status: 429 });
  }

  // Content Security Policy
  // Next.js injects inline scripts for hydration that can't use nonces in RSC mode,
  // so 'unsafe-inline' is required. @n3rd-ai/ui loads fonts from jsdelivr CDN.
  const cspDirectives = [
    `default-src 'self'`,
    `script-src 'self' 'unsafe-inline' 'unsafe-eval'`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self' https://cdn.jsdelivr.net`,
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
