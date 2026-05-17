import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";
import { APP_VERSION, CATEGORY_COUNT, PATTERN_COUNT } from "@/lib/constants";

describe("Home page", () => {
  it("renders the hero heading", () => {
    render(<Home />);
    expect(screen.getByText(/stop pii from leaking to llms/i)).toBeInTheDocument();
  });

  it("flags the product as beta", () => {
    render(<Home />);
    expect(screen.getAllByText(/beta/i).length).toBeGreaterThan(0);
  });

  it("renders the download button", () => {
    render(<Home />);
    expect(screen.getAllByText(/download for macos/i).length).toBeGreaterThan(0);
  });

  it("renders the privacy section", () => {
    render(<Home />);
    expect(screen.getAllByText(/your prompts never leave your mac/i).length).toBeGreaterThan(0);
  });

  it("surfaces the new PII redaction section", () => {
    render(<Home />);
    expect(screen.getByText(/keep your data out of model logs/i)).toBeInTheDocument();
  });

  it("advertises the current pattern and category counts", () => {
    render(<Home />);
    expect(screen.getAllByText(new RegExp(`${PATTERN_COUNT}`)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(new RegExp(`${CATEGORY_COUNT}`)).length).toBeGreaterThan(0);
  });

  it("shows the benchmark section", () => {
    render(<Home />);
    expect(screen.getByText(/measured, not marketed/i)).toBeInTheDocument();
    expect(screen.getAllByText(/attacks caught/i).length).toBeGreaterThan(0);
  });

  it("shows enterprise features", () => {
    render(<Home />);
    expect(screen.getByText(/ready for your security team/i)).toBeInTheDocument();
    expect(screen.getAllByText(/mdm managed/i).length).toBeGreaterThan(0);
  });

  it("surfaces new category coverage", () => {
    render(<Home />);
    expect(screen.getAllByText(/tool poisoning/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/multilingual/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/alignment bypass/i).length).toBeGreaterThan(0);
  });

  it("shows the current app version", () => {
    render(<Home />);
    expect(screen.getAllByText(new RegExp(`v${APP_VERSION}`)).length).toBeGreaterThan(0);
  });
});
