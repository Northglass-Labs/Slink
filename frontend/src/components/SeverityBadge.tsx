import type { Detection } from "../types";

interface Props {
  severity: Detection["severity"];
}

// Semantic severity colors — critical/high/medium/low
const severityConfig: Record<
  Detection["severity"],
  { background: string; color: string; label: string }
> = {
  critical: {
    background: "rgba(239, 68, 68, 0.12)",
    color: "var(--color-sev-critical)",
    label: "Critical",
  },
  high: {
    background: "rgba(249, 115, 22, 0.12)",
    color: "var(--color-sev-high)",
    label: "High",
  },
  medium: {
    background: "rgba(251, 191, 36, 0.10)",
    color: "var(--color-sev-medium)",
    label: "Medium",
  },
  low: {
    background: "rgba(139, 159, 192, 0.08)",
    color: "var(--color-sev-low)",
    label: "Low",
  },
};

export default function SeverityBadge({ severity }: Props) {
  const { background, color, label } = severityConfig[severity];

  return (
    <span
      style={{
        display: "inline-flex",
        padding: "3px 8px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 500,
        letterSpacing: "0.4px",
        background,
        color,
        textTransform: "uppercase",
      }}
    >
      {label}
    </span>
  );
}

// severityBorderColor moved to ./severityStyles — keeping this file component-only
// satisfies react-refresh/only-export-components.
