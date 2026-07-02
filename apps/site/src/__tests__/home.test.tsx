import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";
import { APP_VERSION } from "@/lib/constants";

describe("Home page", () => {
  it("renders the hero heading", () => {
    render(<Home />);
    expect(screen.getByText(/your ai agent can use your secrets/i)).toBeInTheDocument();
    expect(screen.getByText(/it never sees them/i)).toBeInTheDocument();
  });

  it("leads with the secret keeper and the agent surface", () => {
    render(<Home />);
    expect(screen.getByText(/you keep the secret/i)).toBeInTheDocument();
    expect(screen.getByText(/drive it from claude code/i)).toBeInTheDocument();
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
