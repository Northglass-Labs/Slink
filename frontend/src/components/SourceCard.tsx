import type { SourceStatus } from "../types";
import api from "../api";
import { timeAgo } from "../utils/time";

// Health: 0 failures = healthy, 1-2 = degraded, 3+ = failing
function healthIndicator(failures: number): {
  color: string;
  bg: string;
  label: string;
} {
  if (failures === 0)
    return {
      color: "var(--color-success)",
      bg: "rgba(52,211,153,0.12)",
      label: "Healthy",
    };
  if (failures <= 2)
    return {
      color: "var(--color-warning)",
      bg: "rgba(251,191,36,0.12)",
      label: "Degraded",
    };
  return {
    color: "var(--color-danger)",
    bg: "rgba(239,68,68,0.12)",
    label: "Failing",
  };
}

// Convert snake_case source names to Title Case for display
function formatSourceName(name: string): string {
  return name
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

interface Props {
  source: SourceStatus;
  isAdmin: boolean;
  onToggle: (updated: SourceStatus) => void;
}

export default function SourceCard({ source, isAdmin, onToggle }: Props) {
  const { color, bg, label } = healthIndicator(source.consecutive_failures);

  async function handleToggle() {
    try {
      const res = await api.patch<SourceStatus>(`/sources/${source.source_name}`, {
        enabled: !source.enabled,
      });
      onToggle(res.data);
    } catch {
      // Surface failure silently — user can retry
    }
  }

  const statLabel: React.CSSProperties = {
    fontSize: 10,
    fontWeight: 500,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
    color: "var(--color-text-tertiary)",
  };

  const statValue: React.CSSProperties = {
    fontSize: 13,
    color: "var(--color-text-secondary)",
    marginTop: 2,
  };

  return (
    <div
      style={{
        background: "var(--color-surface-1)",
        border: "1px solid var(--color-border)",
        borderRadius: 10,
        padding: 16,
        display: "flex",
        flexDirection: "column",
        gap: 12,
      }}
    >
      {/* Header row */}
      <div className="flex items-start justify-between">
        <div>
          <h3
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: "var(--color-text-primary)",
              margin: 0,
            }}
          >
            {formatSourceName(source.source_name)}
          </h3>
          {/* Health indicator pill */}
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              marginTop: 4,
              padding: "2px 8px",
              borderRadius: 4,
              fontSize: 11,
              fontWeight: 500,
              background: bg,
              color,
            }}
          >
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: color,
                flexShrink: 0,
              }}
            />
            {label}
          </span>
        </div>

        {/* Enabled/Disabled toggle */}
        {isAdmin ? (
          <button
            onClick={handleToggle}
            style={{
              padding: "4px 10px",
              borderRadius: 5,
              fontSize: 11,
              fontWeight: 500,
              cursor: "pointer",
              transition: "opacity 120ms ease",
              background: source.enabled
                ? "rgba(52,211,153,0.12)"
                : "var(--color-surface-3)",
              border: source.enabled
                ? "1px solid rgba(52,211,153,0.25)"
                : "1px solid var(--color-border)",
              color: source.enabled
                ? "var(--color-success)"
                : "var(--color-text-tertiary)",
            }}
          >
            {source.enabled ? "Enabled" : "Disabled"}
          </button>
        ) : (
          <span
            style={{
              padding: "4px 10px",
              borderRadius: 5,
              fontSize: 11,
              fontWeight: 500,
              background: source.enabled
                ? "rgba(52,211,153,0.12)"
                : "var(--color-surface-3)",
              border: source.enabled
                ? "1px solid rgba(52,211,153,0.25)"
                : "1px solid var(--color-border)",
              color: source.enabled
                ? "var(--color-success)"
                : "var(--color-text-tertiary)",
            }}
          >
            {source.enabled ? "Enabled" : "Disabled"}
          </span>
        )}
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-3">
        <div>
          <p style={statLabel}>Last Poll</p>
          <p style={statValue}>{timeAgo(source.last_poll)}</p>
        </div>
        <div>
          <p style={statLabel}>Last Success</p>
          <p style={statValue}>{timeAgo(source.last_success)}</p>
        </div>
        <div>
          <p style={statLabel}>Failures</p>
          <p
            style={{
              ...statValue,
              fontWeight: 600,
              color:
                source.consecutive_failures === 0
                  ? "var(--color-success)"
                  : source.consecutive_failures <= 2
                  ? "var(--color-warning)"
                  : "var(--color-danger)",
            }}
          >
            {source.consecutive_failures}
          </p>
        </div>
        <div>
          <p style={statLabel}>Poll Interval</p>
          <p style={statValue}>{source.poll_interval_seconds}s</p>
        </div>
      </div>
    </div>
  );
}
