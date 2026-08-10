"use client";

import { useState } from "react";
import Link from "next/link";

export function MobileNav({ downloadUrl }: { downloadUrl: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="sm:hidden">
      <button
        onClick={() => setOpen(!open)}
        className="text-text-secondary hover:text-text p-1"
        aria-label={open ? "Close menu" : "Open menu"}
        aria-expanded={open}
      >
        {open ? (
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <path d="M6 6l12 12M6 18L18 6" strokeLinecap="round" />
          </svg>
        ) : (
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <path d="M4 8h16M4 16h16" strokeLinecap="round" />
          </svg>
        )}
      </button>

      {open && (
        <div className="border-border absolute left-0 right-0 top-full border-b bg-white px-6 py-4">
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <span className="rounded-md border border-amber-300 bg-amber-50 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-amber-800">
                Beta
              </span>
              <span className="text-text-secondary text-xs">Experimental — not for production</span>
            </div>
            <a
              href="#playground"
              onClick={() => setOpen(false)}
              className="text-text-secondary hover:text-text py-1 text-sm"
            >
              Live demo
            </a>
            <a
              href="#how"
              onClick={() => setOpen(false)}
              className="text-text-secondary hover:text-text py-1 text-sm"
            >
              How it works
            </a>
            <a
              href="#agents"
              onClick={() => setOpen(false)}
              className="text-text-secondary hover:text-text py-1 text-sm"
            >
              For agents
            </a>
            <Link
              href="/privacy"
              onClick={() => setOpen(false)}
              className="text-text-secondary hover:text-text py-1 text-sm"
            >
              Privacy
            </Link>
            <a
              href={downloadUrl}
              className="bg-bouclier rounded-lg px-4 py-2.5 text-center text-sm font-medium text-white"
            >
              Download
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
