export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-white px-6 text-center">
      <h1 className="text-text text-8xl font-bold tracking-tight">404</h1>
      <p className="text-text-secondary mt-4 text-lg">
        What you&apos;re looking for doesn&apos;t exist.
      </p>
      <a
        href="/"
        className="bg-bouclier hover:bg-bouclier-dark mt-8 rounded-xl px-6 py-3 text-sm font-semibold text-white shadow-sm transition-all hover:shadow-md"
      >
        Back to Bouclier.ai
      </a>
    </main>
  );
}
