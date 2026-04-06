import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";
import { APP_VERSION, CATEGORY_COUNT, PATTERN_COUNT } from "@/lib/constants";

describe("Home page", () => {
  it("renders the hero heading", () => {
    render(<Home />);
    expect(screen.getByText(/prompt injection firewall for macos/i)).toBeInTheDocument();
  });

  it("renders the download button", () => {
    render(<Home />);
    expect(screen.getByText(/download for macos/i)).toBeInTheDocument();
  });

  it("renders the privacy section", () => {
    render(<Home />);
    expect(screen.getByText(/privacy by design/i)).toBeInTheDocument();
  });

  it("advertises the current pattern and category counts", () => {
    render(<Home />);
    const paragraphMatches = screen.getAllByText(
      new RegExp(`${PATTERN_COUNT}.*${CATEGORY_COUNT} categories`, "i"),
    );
    expect(paragraphMatches.length).toBeGreaterThan(0);
  });

  it("shows the benchmark section", () => {
    render(<Home />);
    expect(screen.getByText(/measured, not marketed/i)).toBeInTheDocument();
    expect(screen.getAllByText(/true-positive rate/i).length).toBeGreaterThan(0);
  });

  it("shows enterprise features", () => {
    render(<Home />);
    expect(screen.getByText(/enterprise-ready/i)).toBeInTheDocument();
    expect(screen.getAllByText(/mdm managed/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/streaming response scan/i).length).toBeGreaterThan(0);
  });

  it("surfaces new category coverage", () => {
    render(<Home />);
    expect(screen.getAllByText(/tool poisoning/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/multilingual/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/alignment bypass/i).length).toBeGreaterThan(0);
  });

  it("shows the current app version in the status line", () => {
    render(<Home />);
    expect(screen.getByText(new RegExp(`v${APP_VERSION}`))).toBeInTheDocument();
  });
});
