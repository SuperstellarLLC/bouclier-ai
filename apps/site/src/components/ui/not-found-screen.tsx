import Image from "next/image";

interface NotFoundScreenProps {
  heading?: string;
  message?: string;
}

export function NotFoundScreen({
  heading = "404",
  message = "What you're looking for doesn't exist, sailor.",
}: NotFoundScreenProps) {
  return (
    <main className="relative min-h-screen w-full overflow-hidden bg-black text-white">
      <Image
        src="/images/kraken-404.jpg"
        alt="Colossal octopus rising from a stormy ocean"
        fill
        priority
        sizes="100vw"
        className="object-cover"
      />
      <div
        className="absolute inset-0 bg-gradient-to-b from-black/80 via-black/40 to-black/80"
        aria-hidden="true"
      />
      <div className="relative z-10 flex min-h-screen flex-col items-center justify-center px-6 py-16 text-center">
        <section className="rounded-[32px] bg-black/35 px-10 py-16 text-white/90 shadow-[0_30px_70px_-40px_rgba(15,23,42,0.65)] backdrop-blur-2xl">
          <h1 className="text-[clamp(144px,22vw,320px)] font-bold leading-none tracking-[0.02em] text-white mix-blend-difference">
            {heading}
          </h1>
          <p className="mt-8 text-lg font-medium text-white/85">{message}</p>
        </section>
      </div>
    </main>
  );
}
