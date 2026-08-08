import { ImageResponse } from "next/og";
import { readFileSync } from "fs";
import { join } from "path";

export const runtime = "nodejs";
export const alt = "Bouclier.ai — A prompt-injection firewall for your AI agent";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OGImage() {
  const logoData = readFileSync(join(process.cwd(), "public/images/logo-256.png"));
  const logoBase64 = `data:image/png;base64,${logoData.toString("base64")}`;

  return new ImageResponse(
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        width: "100%",
        height: "100%",
        background: "linear-gradient(135deg, #f8fafc 0%, #e8f0fe 50%, #f8fafc 100%)",
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <img src={logoBase64} width={96} height={96} style={{ borderRadius: 20 }} alt="" />

      <div
        style={{
          display: "flex",
          fontSize: 56,
          fontWeight: 700,
          color: "#0f172a",
          marginTop: 24,
          letterSpacing: "-0.025em",
        }}
      >
        Bouclier.ai
      </div>

      <div
        style={{
          display: "flex",
          fontSize: 24,
          color: "#64748b",
          marginTop: 12,
        }}
      >
        A web page should not be able to give your agent orders.
      </div>

      <div
        style={{
          display: "flex",
          gap: 32,
          marginTop: 40,
        }}
      >
        {[
          { value: "161", label: "Detection patterns" },
          { value: "0", label: "Certificates installed" },
          { value: "MCP", label: "Native agent support" },
        ].map((m) => (
          <div
            key={m.label}
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              padding: "16px 24px",
              background: "white",
              borderRadius: 12,
              border: "1px solid #e2e8f0",
            }}
          >
            <div style={{ fontSize: 28, fontWeight: 700, color: "#0f172a" }}>{m.value}</div>
            <div style={{ fontSize: 14, color: "#64748b", marginTop: 4 }}>{m.label}</div>
          </div>
        ))}
      </div>
    </div>,
    { ...size },
  );
}
