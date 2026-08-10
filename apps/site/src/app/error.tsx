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
    <main className="text-text flex min-h-screen flex-col items-center justify-center bg-white px-6 text-center">
      <h1 className="text-6xl font-bold">Something went wrong</h1>
      <p className="text-text-secondary mt-4 text-lg">
        An unexpected error occurred. Please try again.
      </p>
      <button
        onClick={reset}
        className="bg-bouclier hover:bg-bouclier-dark mt-8 rounded-xl px-6 py-3 text-sm font-semibold text-white shadow-sm transition-all hover:shadow-md"
      >
        Try again
      </button>
    </main>
  );
}
