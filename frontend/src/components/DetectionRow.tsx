import { useMemo } from "react";
import type { Detection } from "../types";
import SeverityBadge from "./SeverityBadge";
import { severityBorderColor } from "./severityStyles";
import { timeAgo } from "../utils/time";

// Maps a source name to its investigation dashboard URL.
// Keeps the row tidy — just an icon link, full investigate section is in DetectionDetail.
// Falcon links use the us-1 region (CrowdStrike's doc default); swap the
// subdomain if your tenant is on us-2 / eu-1 / us-gov-1.
const SOURCE_DASHBOARDS: Record<string, string> = {
  crowdstrike_recon: "https://falcon.us-1.crowdstrike.com/intelligence-v2/recon",
  ransomwatch: "https://ransomware.live",
  ransomlook: "https://www.ransomlook.io/recent",
  alienvault_otx: "https://otx.alienvault.com/dashboard",
  crowdstrike_intel: "https://falcon.us-1.crowdstrike.com/intelligence-v2/reports",
};

// Maps a source slug to its display label. Falls back to the raw slug when
// not present, so adding a new collector never breaks rendering.
const SOURCE_LABELS: Record<string, string> = {
  urlhaus: "URLhaus",
  malwarebazaar: "MalwareBazaar",
  feodo_tracker: "Feodo Tracker",
  nvd: "NVD",
  github_advisory: "GitHub Advisories",
};

interface Props {
  detection: Detection;
  isExpanded: boolean;
  onToggle: () => void;
  isFirst?: boolean;
  selected?: boolean;
  onSelect?: (id: number) => void;
  isActive?: boolean;
}

// Config for non-"new" statuses: micro-label text and its color.
// Keeps the indicator definition co-located with the row rendering logic.
const STATUS_INDICATOR: Record<string, { label: string; color: string; bg: string }> = {
  acknowledged: { label: "ACK", color: "#6b7280", bg: "rgba(107,114,128,0.15)" },
  dismissed:    { label: "DIS", color: "#9ca3af", bg: "rgba(156,163,175,0.12)" },
  escalated:    { label: "ESC", color: "#ef4444", bg: "rgba(239,68,68,0.15)"   },
};

export default function DetectionRow({ detection, isExpanded, onToggle, isFirst = false, selected = false, onSelect, isActive = false }: Props) {
  const borderColor = severityBorderColor(detection.severity);

  // Row-level style overrides driven by triage status.
  // "new" is the default — no override needed.
  const statusStyle = useMemo(() => {
    switch (detection.status) {
      case "acknowledged":
        return { opacity: 0.65 };
      case "dismissed":
        return { opacity: 0.5 };
      case "escalated":
        // Overrides the severity left-border with danger red so escalated rows
        // stand out even when severity is low.
        return {
          borderLeftColor: "var(--color-danger, #ef4444)",
          borderLeftWidth: "3px",
        };
      default:
        return {};
    }
  }, [detection.status]);

  const indicator = STATUS_INDICATOR[detection.status];

  return (
    <tr
      style={{
        cursor: "pointer",
        transition: "background-color 120ms ease, opacity 120ms ease",
        backgroundColor: isExpanded
          ? "var(--color-surface-2)"
          : isActive
            ? "var(--color-surface-2)"
            : "transparent",
        borderLeft: `3px solid ${borderColor}`,
        borderTop: isFirst ? "none" : "1px solid var(--color-border)",
        // Subtle outline for keyboard-active row so it's distinguishable from hover
        outline: isActive ? "1px solid var(--color-accent)" : "none",
        outlineOffset: -1,
        // Merge status-driven overrides last so they take precedence where needed
        ...statusStyle,
      }}
      onMouseOver={(e) => {
        if (!isExpanded && !isActive) {
          (e.currentTarget as HTMLTableRowElement).style.backgroundColor = "var(--color-hover)";
        }
      }}
      onMouseOut={(e) => {
        if (!isExpanded && !isActive) {
          (e.currentTarget as HTMLTableRowElement).style.backgroundColor = "transparent";
        }
      }}
      onClick={onToggle}
    >
      {/* Selection checkbox */}
      {onSelect && (
        <td
          className="px-3 py-3"
          style={{ width: 32 }}
          onClick={(e) => e.stopPropagation()}
        >
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onSelect(detection.id)}
            style={{
              accentColor: "var(--color-accent)",
              cursor: "pointer",
              width: 15,
              height: 15,
            }}
          />
        </td>
      )}

      {/* Severity badge */}
      <td className="px-4 py-3 whitespace-nowrap">
        <SeverityBadge severity={detection.severity} />
      </td>

      {/* Source — with small external-link icon to the source dashboard */}
      <td
        className="px-4 py-3 whitespace-nowrap text-sm"
        style={{ color: "var(--color-text-secondary)" }}
      >
        <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
          {SOURCE_LABELS[detection.source] ?? detection.source}
          {SOURCE_DASHBOARDS[detection.source] && (
            <a
              href={SOURCE_DASHBOARDS[detection.source]}
              target="_blank"
              rel="noopener noreferrer"
              title={`Open ${detection.source} dashboard`}
              onClick={(e) => e.stopPropagation()}
              style={{ color: "var(--color-text-tertiary)", lineHeight: 1 }}
            >
              {/* External link icon — 10px, matches row text weight */}
              <svg width="10" height="10" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M10 7v3H2V3h3M7 2h3v3M5.5 6.5 10 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </a>
          )}
          {/* Status micro-pill — only shown for non-new statuses so the feed stays clean */}
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
                lineHeight: "16px",
              }}
            >
              {indicator.label}
            </span>
          )}
        </span>
      </td>

      {/* Title — strikethrough for dismissed rows signals the detection is no longer active */}
      <td
        className="px-4 py-3 text-sm max-w-xs truncate"
        style={{
          color: "var(--color-text-primary)",
          textDecoration: detection.status === "dismissed" ? "line-through" : "none",
          textDecorationColor: "var(--color-text-tertiary)",
        }}
      >
        {detection.title}
      </td>

      {/* Matched keywords */}
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {detection.matched_keywords.slice(0, 4).map((kw) => (
            <span
              key={kw}
              style={{
                padding: "2px 6px",
                borderRadius: 4,
                fontSize: 11,
                background: "var(--color-surface-3)",
                color: "var(--color-text-secondary)",
              }}
            >
              {kw}
            </span>
          ))}
          {detection.matched_keywords.length > 4 && (
            <span
              style={{
                padding: "2px 6px",
                borderRadius: 4,
                fontSize: 11,
                background: "var(--color-surface-3)",
                color: "var(--color-text-tertiary)",
              }}
            >
              +{detection.matched_keywords.length - 4}
            </span>
          )}
        </div>
      </td>

      {/* Timestamp — relative + absolute on hover via title attr */}
      <td
        className="px-4 py-3 whitespace-nowrap text-sm"
        style={{ color: "var(--color-text-tertiary)" }}
        title={new Date(detection.first_seen).toLocaleString()}
      >
        <span style={{ color: "var(--color-text-secondary)" }}>
          {timeAgo(detection.first_seen)}
        </span>
        <span className="block text-[11px]">
          {new Date(detection.first_seen).toLocaleDateString()}
        </span>
      </td>

      {/* Expand indicator */}
      <td
        className="px-4 py-3 text-xs whitespace-nowrap"
        style={{ color: "var(--color-text-tertiary)" }}
      >
        {isExpanded ? "▲" : "▼"}
      </td>
    </tr>
  );
}
