"use client";

import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log to error reporting service (e.g., Sentry)
    console.error("Unhandled error:", error);
  }, [error]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-black px-6 text-center text-white">
      <h1 className="text-6xl font-bold">Something went wrong</h1>
      <p className="mt-4 text-lg text-white/70">An unexpected error occurred. Please try again.</p>
      <button
        onClick={reset}
        className="mt-8 rounded-lg bg-white/10 px-6 py-3 text-sm font-medium text-white backdrop-blur-sm transition-colors hover:bg-white/20"
      >
        Try again
      </button>
    </main>
  );
}
