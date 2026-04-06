import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Bouclier.ai — Prompt Injection Firewall for macOS";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OGImage() {
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
      {/* Shield icon */}
      <svg
        width="80"
        height="80"
        viewBox="0 0 24 24"
        fill="none"
        stroke="#1a56db"
        strokeWidth="1.5"
      >
        <path
          d="M12 3l7.5 3.5v5c0 4.5-3 8.5-7.5 10-4.5-1.5-7.5-5.5-7.5-10v-5L12 3z"
          fill="#1a56db"
          fillOpacity="0.08"
          stroke="#1a56db"
        />
        <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>

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
        Prompt Injection Firewall for macOS
      </div>

      <div
        style={{
          display: "flex",
          gap: 32,
          marginTop: 40,
        }}
      >
        {[
          { value: "161", label: "Patterns" },
          { value: "21", label: "Categories" },
          { value: "91.9%", label: "TPR" },
          { value: "2.9%", label: "FPR" },
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
