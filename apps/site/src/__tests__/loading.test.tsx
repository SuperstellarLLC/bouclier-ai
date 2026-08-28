import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import Loading from "@/app/loading";

describe("Loading", () => {
  it("announces progress without exposing the decorative spinner", () => {
    render(<Loading />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading Bouclier.ai");
  });
});
