import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import BlockedPage from "@/app/blocked/page";
import PrivacyPage from "@/app/privacy/page";
import TermsPage from "@/app/terms/page";

describe("truthful privacy and recovery copy", () => {
  it("distinguishes local inspection from provider and hosting data flows", () => {
    render(<PrivacyPage />);

    expect(screen.getByText(/allowed ai requests and responses still travel/i)).toBeInTheDocument();
    expect(screen.getAllByText(/ordinary http transport metadata/i).length).toBeGreaterThan(0);
    expect(
      screen.getByText(/on-device redaction is best effort, not a guarantee/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/best-effort-redacted classifier passage/i)).toBeInTheDocument();
    expect(
      screen.getByText(/removing the app bundle does not automatically delete/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/fingerprint, and nonce for 180 seconds/i)).toBeInTheDocument();
    expect(screen.getByText(/recent-event list is capped at 5,000 entries/i)).toBeInTheDocument();
    expect(
      screen.getByText(/counters are retained.*until the download store is reset/i),
    ).toBeInTheDocument();
    expect(screen.getByText("90 days")).toBeInTheDocument();
    expect(screen.queryByText(/^none by default/i)).not.toBeInTheDocument();
  });

  it("scopes the Terms local-processing claim to detection", () => {
    render(<TermsPage />);

    expect(
      screen.getByRole("heading", { name: /local detection and limited data flows/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/explicitly submit a false-positive report/i)).toBeInTheDocument();
    expect(screen.getByText(/visible partial-coverage warning/i)).toBeInTheDocument();
    expect(screen.getByText(/64 MiB transport limit/i)).toBeInTheDocument();
    expect(screen.getByText(/built with llama/i)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /no data collection/i })).not.toBeInTheDocument();
  });

  it("leads false-positive recovery with a narrow unblock action", () => {
    render(<BlockedPage />);

    expect(screen.getByText(/choose unblock/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /review and unblock/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /report after review/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /monitor as a fallback/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /how bouclier classified/i })).toBeInTheDocument();
    expect(screen.getByText(/does not track file taint or write history/i)).toBeInTheDocument();
    expect(screen.getByText(/project-local path alone is not enough/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/project-local files remain trusted/i);
    expect(document.body.textContent).not.toMatch(/this was not something you typed/i);
  });
});
