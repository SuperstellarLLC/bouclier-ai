"use client";

import { useEffect } from "react";
import Link from "next/link";

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
    <main className="text-text flex min-h-screen flex-col items-center justify-center bg-white px-6 text-center">
      <div role="alert">
        <h1 className="text-4xl font-bold sm:text-6xl">Something went wrong</h1>
        <p className="text-text-secondary mt-4 text-lg">
          An unexpected error occurred. Please try again.
        </p>
      </div>
      <div className="mt-8 flex flex-col gap-3 sm:flex-row">
        <button
          type="button"
          onClick={reset}
          className="bg-bouclier hover:bg-bouclier-dark rounded-xl px-6 py-3 text-sm font-semibold text-white shadow-sm transition-all hover:shadow-md"
        >
          Try again
        </button>
        <Link
          href="/"
          className="border-border text-text hover:border-bouclier/30 rounded-xl border bg-white px-6 py-3 text-sm font-semibold shadow-sm transition-all hover:shadow-md"
        >
          Back to home
        </Link>
      </div>
    </main>
  );
}
