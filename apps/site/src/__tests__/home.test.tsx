import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";
import { APP_VERSION } from "@/lib/constants";

describe("Home page", () => {
  it("renders the hero heading", () => {
    render(<Home />);
    expect(screen.getByText(/a web page should not be able/i)).toBeInTheDocument();
    expect(screen.getByText(/to give your agent orders/i)).toBeInTheDocument();
  });

  it("leads with prompt-injection defence, split by provenance", () => {
    render(<Home />);
    expect(screen.getByText(/it knows which bytes you wrote/i)).toBeInTheDocument();
    expect(screen.getByText(/untrusted — flagged, or refused/i)).toBeInTheDocument();
    expect(screen.getByText(/yours — never blocked/i)).toBeInTheDocument();
  });

  it("documents the agent surface and no longer mentions the secret keeper", () => {
    render(<Home />);
    expect(screen.getByText(/drive it from claude code/i)).toBeInTheDocument();
    expect(screen.queryByText(/secret keeper/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/you keep the secret/i)).not.toBeInTheDocument();
  });

  it("renders the live playground", () => {
    render(<Home />);
    expect(screen.getByText(/same words\. different verdict/i)).toBeInTheDocument();
    expect(
      screen.getByRole("radiogroup", { name: /where this content came from/i }),
    ).toBeInTheDocument();
  });

  it("does not overclaim — states the limits of detection", () => {
    render(<Home />);
    expect(screen.getByText(/what it does not claim/i)).toBeInTheDocument();
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
    expect(screen.getAllByText(/nothing leaves your mac/i).length).toBeGreaterThan(0);
  });

  it("surfaces the trust section that pins prompt + header passthrough", () => {
    render(<Home />);
    expect(screen.getByText(/what reaches the model — and what doesn/i)).toBeInTheDocument();
  });

  it("shows enterprise features", () => {
    render(<Home />);
    expect(screen.getByText(/ready for your security team/i)).toBeInTheDocument();
    expect(screen.getAllByText(/mdm managed/i).length).toBeGreaterThan(0);
  });

  it("shows the current app version", () => {
    render(<Home />);
    expect(screen.getAllByText(new RegExp(`v${APP_VERSION}`)).length).toBeGreaterThan(0);
  });
});
