import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { MobileNav } from "@/app/mobile-nav";

describe("MobileNav", () => {
  it("exposes all legal links and closes on Escape", () => {
    render(<MobileNav downloadUrl="/api/download?v=1.0.0&c=site" />);

    const trigger = screen.getByRole("button", { name: /open menu/i });
    fireEvent.click(trigger);

    expect(screen.getByRole("link", { name: "Privacy" })).toHaveAttribute("href", "/privacy");
    expect(screen.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("link", { name: "Terms" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});
