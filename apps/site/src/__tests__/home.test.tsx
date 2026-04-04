import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";

describe("Home page", () => {
  it("renders the 404 heading", () => {
    render(<Home />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("404");
  });

  it("renders the sailor message", () => {
    render(<Home />);
    expect(screen.getByText(/doesn't exist, sailor/i)).toBeInTheDocument();
  });

  it("renders the background image", () => {
    render(<Home />);
    const img = screen.getByAltText("Colossal octopus rising from a stormy ocean");
    expect(img).toBeInTheDocument();
  });
});
