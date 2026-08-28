export default function Loading() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-white">
      <div role="status" aria-live="polite" className="flex flex-col items-center gap-3">
        <div
          aria-hidden="true"
          className="border-bouclier/20 border-t-bouclier h-8 w-8 animate-spin rounded-full border-2 motion-reduce:animate-none"
        />
        <span className="sr-only">Loading Bouclier.ai…</span>
      </div>
    </main>
  );
}
