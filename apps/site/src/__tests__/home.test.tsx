import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";

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
});
