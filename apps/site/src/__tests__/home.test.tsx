import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";
import { BENCHMARK_PROVENANCE } from "@/lib/benchmark-provenance";
import { APP_VERSION } from "@/lib/constants";

describe("Home page", () => {
  it("renders the hero heading", () => {
    render(<Home />);
    expect(screen.getByText(/web pages should not/i)).toBeInTheDocument();
    expect(screen.getByText(/give your agents instructions/i)).toBeInTheDocument();
  });

  it("leads with prompt-injection defence, split by provenance", () => {
    render(<Home />);
    expect(screen.getByText(/it acts on origins the request can attribute/i)).toBeInTheDocument();
    expect(screen.getByText(/untrusted — flagged, or refused/i)).toBeInTheDocument();
    expect(
      screen.getByText(/attributed local read — forwarded in normal mode/i),
    ).toBeInTheDocument();
  });

  it("describes authored file reads as a narrow, fail-closed attribution", () => {
    render(<Home />);
    const copy = document.body.textContent ?? "";

    expect(copy).toMatch(/positively attribute/i);
    expect(copy).toMatch(/canonical, non-vendored path/i);
    expect(copy).toMatch(/missing or ambiguous (attribution|link).+stays untrusted/i);
    expect(copy).toMatch(/does not track file taint/i);
    expect(copy).toMatch(/request-local classification/i);
    expect(copy).toMatch(/silently saved.+later linked read can look authored/i);
    expect(copy).not.toMatch(/a file read from a path you control is trusted/i);
    expect(copy).not.toMatch(/files you read from your own project/i);
    expect(copy).not.toMatch(/fetch itself is inspected before/i);
    expect(copy).not.toMatch(/knows which bytes you wrote/i);
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
    expect(screen.getByRole("group", { name: /content source/i })).toBeInTheDocument();
  });

  it("models the real monitor-by-default flow before blocking is enabled", () => {
    render(<Home />);

    const monitor = screen.getByRole("radio", { name: /monitor/i });
    const blocking = screen.getByRole("radio", { name: /^blocking/i });
    expect(monitor).toBeChecked();
    expect(blocking).not.toBeChecked();
    expect(screen.getByText("WOULD REFUSE")).toBeInTheDocument();
    expect(screen.getAllByText(/forwarded in monitor mode/i).length).toBeGreaterThan(0);

    fireEvent.click(blocking);
    expect(screen.getByText("REFUSED")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("radio", { name: /you typed it/i }));
    expect(screen.getByText("FORWARDED")).toBeInTheDocument();
    expect(screen.getByText(/principal-only request bypasses/i)).toBeInTheDocument();
  });

  it("does not overclaim — states the limits of detection", () => {
    render(<Home />);
    expect(screen.getByText(/what it does not claim/i)).toBeInTheDocument();
    expect(screen.getByText(/does not approve, block, or undo/i)).toBeInTheDocument();
    expect(screen.queryByText(/register the read-only status MCP/i)).not.toBeInTheDocument();
    expect(screen.getByText(/ships a read-only/i)).toBeInTheDocument();
    expect(screen.queryByText(/additional AI domains/i)).not.toBeInTheDocument();
  });

  it("flags the product as beta", () => {
    render(<Home />);
    expect(screen.getAllByText(/beta/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/built with llama/i)).toBeInTheDocument();
    expect(screen.getByText(/source code is Apache-2\.0 open source/i)).toHaveTextContent(
      /separate Llama 4 Community License/i,
    );
  });

  it("renders the download button", () => {
    render(<Home />);
    expect(screen.getAllByText(/download for macos/i).length).toBeGreaterThan(0);
  });

  it("renders the privacy section", () => {
    render(<Home />);
    expect(screen.getAllByText(/detection stays on your mac/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/routine scan logs never contain your prompts/i)).toBeInTheDocument();
    expect(screen.getByText(/optional block-sample capture is off by default/i)).toHaveTextContent(
      /false-positive report leaves your Mac only after you review its contents and confirm sending it/i,
    );
  });

  it("surfaces the trust section that pins prompt + header passthrough", () => {
    render(<Home />);
    expect(screen.getByText(/what reaches the model — and what doesn/i)).toBeInTheDocument();
    expect(screen.getByText(/rewrites Host and Content-Length/i)).toBeInTheDocument();
    expect(
      screen.queryByText(/every header reaches the upstream unmodified/i),
    ).not.toBeInTheDocument();
  });

  it("shows enterprise features", () => {
    render(<Home />);
    expect(screen.getByText(/evaluate it with your security team/i)).toBeInTheDocument();
    expect(screen.getAllByText(/mdm managed/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/in-app controls for disabling/i)).toBeInTheDocument();
    expect(screen.getAllByText(/same-user/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/uninstall restrictions/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/there is no agent path to disable/i)).not.toBeInTheDocument();
  });

  it("distinguishes human CLI output from machine JSON", () => {
    render(<Home />);
    expect(screen.getByText(/add --json for machine output/i)).toBeInTheDocument();
    expect(screen.queryByText(/bouclier status returns.+as JSON/i)).not.toBeInTheDocument();
  });

  it("shows the current app version", () => {
    render(<Home />);
    expect(screen.getAllByText(new RegExp(`v${APP_VERSION}`)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/macOS 15\+/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Apple Silicon & Intel/i)).not.toBeInTheDocument();
    expect(screen.getByText(/macOS 15.+Apple silicon/i)).toBeInTheDocument();
  });

  it("pins benchmark copy and reproduction link to the measured release", () => {
    render(<Home />);

    expect(screen.getByTestId("benchmark-provenance")).toHaveTextContent(
      new RegExp(
        `Measured on ${BENCHMARK_PROVENANCE.measuredOnLabel} with Bouclier v${BENCHMARK_PROVENANCE.measuredRelease} at the untrusted blocking threshold of ${BENCHMARK_PROVENANCE.pipeline.untrustedBlockThreshold}`,
      ),
    );
    expect(
      screen.getByText(BENCHMARK_PROVENANCE.measuredOnLabel, { selector: "time" }),
    ).toHaveAttribute("datetime", BENCHMARK_PROVENANCE.measuredOnISO);
    expect(screen.getByTestId("benchmark-provenance")).toHaveTextContent(
      /Newer versions are not represented until the harness is rerun/i,
    );
    expect(screen.getByTestId("benchmark-provenance")).toHaveTextContent(
      /fetched from live Hugging Face dataset endpoints without preserved dataset revisions, input hashes, or a raw result artifact/i,
    );
    expect(
      screen.getByRole("link", {
        name: new RegExp(`Inspect the v${BENCHMARK_PROVENANCE.measuredRelease} harness`),
      }),
    ).toHaveAttribute("href", BENCHMARK_PROVENANCE.sourceUrl);
    expect(screen.getByText(`${BENCHMARK_PROVENANCE.benignCorpus.blockedPercent}%`)).toBeVisible();
    expect(
      screen.getByText(`${BENCHMARK_PROVENANCE.instructionOverrideCorpus.detectedPercent}%`),
    ).toBeVisible();
    expect(document.body.textContent).not.toMatch(/hard one to game/i);
  });
});
