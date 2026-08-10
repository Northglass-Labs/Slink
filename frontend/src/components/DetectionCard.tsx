import type { Detection } from "../types";
import SeverityBadge from "./SeverityBadge";
import { severityBorderColor } from "./severityStyles";
import { timeAgo } from "../utils/time";

interface Props {
  detection: Detection;
  isExpanded: boolean;
  onToggle: () => void;
  selected?: boolean;
  onSelect?: (id: number) => void;
}

const STATUS_INDICATOR: Record<string, { label: string; color: string; bg: string }> = {
  acknowledged: { label: "ACK", color: "#6b7280", bg: "rgba(107,114,128,0.15)" },
  dismissed: { label: "DIS", color: "#9ca3af", bg: "rgba(156,163,175,0.12)" },
  escalated: { label: "ESC", color: "#ef4444", bg: "rgba(239,68,68,0.15)" },
};

// Card layout for narrow viewports (below sm:). The wide table renders
// poorly on phones even with horizontal scroll — this stacks the same
// fields vertically so they're thumb-reachable.
export default function DetectionCard({
  detection,
  isExpanded,
  onToggle,
  selected = false,
  onSelect,
}: Props) {
  const borderColor = severityBorderColor(detection.severity);
  const indicator = STATUS_INDICATOR[detection.status];

  let opacity = 1;
  if (detection.status === "acknowledged") opacity = 0.7;
  if (detection.status === "dismissed") opacity = 0.5;

  return (
    <div
      onClick={onToggle}
      style={{
        cursor: "pointer",
        padding: "12px 14px",
        borderBottom: "1px solid var(--color-border)",
        borderLeft: `3px solid ${borderColor}`,
        background: isExpanded ? "var(--color-surface-2)" : "transparent",
        opacity,
        transition: "background-color 120ms ease, opacity 120ms ease",
      }}
    >
      <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
        {onSelect && (
          <input
            type="checkbox"
            checked={selected}
            onChange={(e) => {
              e.stopPropagation();
              onSelect(detection.id);
            }}
            onClick={(e) => e.stopPropagation()}
            style={{
              accentColor: "var(--color-accent)",
              cursor: "pointer",
              width: 15,
              height: 15,
              marginTop: 2,
              flexShrink: 0,
            }}
          />
        )}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 6,
              flexWrap: "wrap",
            }}
          >
            <SeverityBadge severity={detection.severity} />
            <span
              style={{
                fontSize: 11,
                color: "var(--color-text-secondary)",
              }}
            >
              {detection.source}
            </span>
            {indicator && (
              <span
                style={{
                  padding: "1px 5px",
                  borderRadius: 3,
                  fontSize: 10,
                  fontWeight: 600,
                  letterSpacing: "0.04em",
                  background: indicator.bg,
                  color: indicator.color,
                }}
              >
                {indicator.label}
              </span>
            )}
            <span
              style={{
                marginLeft: "auto",
                fontSize: 11,
                color: "var(--color-text-tertiary)",
              }}
            >
              {timeAgo(detection.first_seen)}
            </span>
          </div>
          <div
            style={{
              fontSize: 13,
              color: "var(--color-text-primary)",
              fontWeight: 500,
              lineHeight: 1.4,
              textDecoration: detection.status === "dismissed" ? "line-through" : "none",
              marginBottom: 6,
            }}
          >
            {detection.title}
          </div>
          {detection.matched_keywords.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {detection.matched_keywords.slice(0, 3).map((kw) => (
                <span
                  key={kw}
                  style={{
                    padding: "1px 6px",
                    borderRadius: 4,
                    fontSize: 10,
                    background: "var(--color-surface-3)",
                    color: "var(--color-text-secondary)",
                  }}
                >
                  {kw}
                </span>
              ))}
              {detection.matched_keywords.length > 3 && (
                <span
                  style={{
                    padding: "1px 6px",
                    borderRadius: 4,
                    fontSize: 10,
                    background: "var(--color-surface-3)",
                    color: "var(--color-text-tertiary)",
                  }}
                >
                  +{detection.matched_keywords.length - 3}
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
