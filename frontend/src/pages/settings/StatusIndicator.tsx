interface StatusIndicatorProps {
  ok: boolean;
  okLabel: string;
  failLabel: string;
}

// Pill-shaped status badge with a colored dot. Used for read-only health
// summaries (notification channels, API sources).
export function StatusIndicator({ ok, okLabel, failLabel }: StatusIndicatorProps) {
  const color = ok ? "var(--color-success)" : "var(--color-danger)";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 10px",
        borderRadius: 4,
        fontSize: 12,
        fontWeight: 500,
        background: ok ? "rgba(52,211,153,0.12)" : "rgba(239,68,68,0.10)",
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
      {ok ? okLabel : failLabel}
    </span>
  );
}
