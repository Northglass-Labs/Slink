import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { DashboardStats } from "../types";
import api from "../api";
import { timeAgo } from "../utils/time";
import { useDashboardStats, dashboardStatsKey } from "../queries/useDashboardStats";

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#FBBF24",
  low: "#A0A0A0",
};

const SEVERITY_BG: Record<string, string> = {
  critical: "rgba(239, 68, 68, 0.12)",
  high: "rgba(245, 158, 11, 0.12)",
  medium: "rgba(251, 191, 36, 0.10)",
  low: "rgba(160, 160, 160, 0.08)",
};

// -------------------------------------------------------------------
// Stat Card component
// -------------------------------------------------------------------

function StatCard({
  label,
  value,
  subtitle,
  valueColor,
}: {
  label: string;
  value: string | number;
  subtitle?: string;
  valueColor?: string;
}) {
  return (
    <div
      style={{
        background: "var(--color-surface-1)",
        border: "1px solid var(--color-border)",
        borderRadius: 10,
        padding: "20px 24px",
      }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: "var(--color-text-tertiary)",
          textTransform: "uppercase",
          letterSpacing: "0.5px",
          marginBottom: 8,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 700,
          color: valueColor || "var(--color-text-primary)",
          lineHeight: 1.1,
        }}
      >
        {value}
      </div>
      {subtitle && (
        <div
          style={{
            fontSize: 12,
            color: "var(--color-text-secondary)",
            marginTop: 6,
          }}
        >
          {subtitle}
        </div>
      )}
    </div>
  );
}

// -------------------------------------------------------------------
// Main Dashboard page
// -------------------------------------------------------------------

export default function DashboardPage() {
  const queryClient = useQueryClient();
  const { data: stats, isLoading, isError } = useDashboardStats();
  const [ackingId, setAckingId] = useState<number | null>(null);
  // Tick state — not read directly, just forces a re-render every minute so
  // timeAgo() values recompute from the current Date.now() rather than staying
  // frozen at the time the component first mounted.
  const [, setTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(id);
  }, []);

  async function handleAck(id: number) {
    setAckingId(id);
    try {
      await api.patch(`/detections/${id}/status`, { status: "acknowledged" });
      // Optimistically update the cached dashboard stats. React Query will
      // refetch on the next 30s tick (or on window focus) and reconcile.
      queryClient.setQueryData<DashboardStats | undefined>(
        dashboardStatsKey,
        (prev) =>
          prev
            ? {
                ...prev,
                needs_attention: prev.needs_attention.filter((d) => d.id !== id),
                acknowledged_count: prev.acknowledged_count + 1,
                new_count: Math.max(0, prev.new_count - 1),
              }
            : prev
      );
    } catch {
      // Silently fail — next refresh will correct the state
    } finally {
      setAckingId(null);
    }
  }

  if (isLoading) {
    return (
      <div style={{ padding: 40, color: "var(--color-text-tertiary)", fontSize: 14 }}>
        Loading dashboard...
      </div>
    );
  }

  if (isError && !stats) {
    return (
      <div style={{ padding: 40, color: "var(--color-danger)", fontSize: 14 }}>
        Failed to load dashboard stats.
      </div>
    );
  }

  if (!stats) return null;

  // Prepare chart data
  const sevDistData = [
    { name: "Critical", value: stats.severity_distribution.critical },
    { name: "High", value: stats.severity_distribution.high },
    { name: "Medium", value: stats.severity_distribution.medium },
    { name: "Low", value: stats.severity_distribution.low },
  ].filter((d) => d.value > 0);

  // Backfill time_series so every day in the window has a row. Recharts
  // 3.x happily renders a chart from {date} points with undefined severity
  // keys, but the bars are then "invisible" because each Bar reads undefined
  // and treats it as 0 height. Filling the gaps also keeps the X axis from
  // jumping around as new days arrive.
  const timeSeriesData = stats.time_series.map((d) => ({
    date: d.date,
    critical: d.critical ?? 0,
    high: d.high ?? 0,
    medium: d.medium ?? 0,
    low: d.low ?? 0,
  }));

  const sevTotal =
    stats.severity_distribution.critical +
    stats.severity_distribution.high +
    stats.severity_distribution.medium +
    stats.severity_distribution.low;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Row 1 — Stat Cards */}
      <div
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4"
        style={{ gap: 16 }}
      >
        <StatCard
          label="Active Detections"
          value={stats.active_count}
          subtitle={`${stats.new_count} new \u00B7 ${stats.acknowledged_count} acknowledged`}
        />
        <StatCard
          label="Critical + High"
          value={stats.critical_count + stats.high_count}
          valueColor="#ef4444"
        />
        <StatCard
          label="Last Critical"
          value={stats.last_critical ? timeAgo(stats.last_critical.first_seen) : "None"}
          subtitle={
            stats.last_critical
              ? `${stats.last_critical.source} \u2014 ${stats.last_critical.title.length > 40 ? stats.last_critical.title.slice(0, 40) + "\u2026" : stats.last_critical.title}`
              : undefined
          }
        />
        <StatCard
          label="Source Health"
          value={`${stats.sources_healthy} / ${stats.sources_total}`}
          subtitle={
            stats.sources_failing === 0
              ? "All sources healthy"
              : `${stats.sources_failing} source${stats.sources_failing > 1 ? "s" : ""} failing`
          }
          valueColor={
            stats.sources_failing === 0
              ? "var(--color-success)"
              : "var(--color-warning)"
          }
        />
      </div>

      {/* Row 2 — Charts */}
      <div
        className="grid grid-cols-1 lg:grid-cols-[1fr_2fr]"
        style={{ gap: 16 }}
      >
        {/* Severity Distribution Donut */}
        <div
          style={{
            background: "var(--color-surface-1)",
            border: "1px solid var(--color-border)",
            borderRadius: 10,
            padding: 20,
          }}
        >
          <div
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: "var(--color-text-tertiary)",
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: 12,
            }}
          >
            Severity Distribution
          </div>
          <div style={{ position: "relative", width: "100%", height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={sevDistData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  dataKey="value"
                  stroke="none"
                >
                  {sevDistData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name.toLowerCase()]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--color-surface-2)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 6,
                    fontSize: 12,
                    color: "var(--color-text-primary)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            {/* Center text */}
            <div
              style={{
                position: "absolute",
                top: "50%",
                left: "50%",
                transform: "translate(-50%, -50%)",
                textAlign: "center",
                pointerEvents: "none",
              }}
            >
              <div
                style={{
                  fontSize: 24,
                  fontWeight: 700,
                  color: "var(--color-text-primary)",
                }}
              >
                {sevTotal}
              </div>
              <div
                style={{
                  fontSize: 10,
                  color: "var(--color-text-tertiary)",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                Total
              </div>
            </div>
          </div>
        </div>

        {/* Detections Over Time — Stacked Bar Chart */}
        <div
          style={{
            background: "var(--color-surface-1)",
            border: "1px solid var(--color-border)",
            borderRadius: 10,
            padding: 20,
          }}
        >
          <div
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: "var(--color-text-tertiary)",
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              marginBottom: 12,
            }}
          >
            Detections Over Time
          </div>
          <div style={{ width: "100%", height: 220 }}>
            {timeSeriesData.length === 0 ? (
              <div
                style={{
                  height: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 12,
                  color: "var(--color-text-tertiary)",
                }}
              >
                No detections in the last 7 days
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={timeSeriesData}>
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "var(--color-text-tertiary)", fontSize: 11 }}
                    axisLine={{ stroke: "var(--color-border)" }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: "var(--color-text-tertiary)", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    width={30}
                    allowDecimals={false}
                  />
                  {/* cursor={{ fill: ... }} controls the hover-highlight rect.
                      In Recharts 3.x the default is an opaque light fill that,
                      against our dark theme, sits as a stuck-looking overlay
                      and can mask the bars underneath. Making it a faint
                      translucent overlay fixes both issues. */}
                  <Tooltip
                    cursor={{ fill: "rgba(148, 163, 184, 0.08)" }}
                    contentStyle={{
                      background: "var(--color-surface-2)",
                      border: "1px solid var(--color-border)",
                      borderRadius: 6,
                      fontSize: 12,
                      color: "var(--color-text-primary)",
                    }}
                  />
                  <Bar
                    dataKey="critical"
                    stackId="a"
                    fill={SEVERITY_COLORS.critical}
                    isAnimationActive={false}
                  />
                  <Bar
                    dataKey="high"
                    stackId="a"
                    fill={SEVERITY_COLORS.high}
                    isAnimationActive={false}
                  />
                  <Bar
                    dataKey="medium"
                    stackId="a"
                    fill={SEVERITY_COLORS.medium}
                    isAnimationActive={false}
                  />
                  <Bar
                    dataKey="low"
                    stackId="a"
                    fill={SEVERITY_COLORS.low}
                    radius={[3, 3, 0, 0]}
                    isAnimationActive={false}
                  />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Row 3 — Needs Attention */}
      <div
        style={{
          background: "var(--color-surface-1)",
          border: "1px solid var(--color-border)",
          borderRadius: 10,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            padding: "12px 20px",
            borderBottom: "1px solid var(--color-border)",
            background: "var(--color-surface-2)",
          }}
        >
          <h2
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--color-text-secondary)",
              textTransform: "uppercase",
              letterSpacing: "0.5px",
              margin: 0,
            }}
          >
            Needs Attention
          </h2>
        </div>
        <div style={{ padding: "12px 20px" }}>
          {stats.needs_attention.length === 0 ? (
            <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", margin: 0 }}>
              No detections need attention right now.
            </p>
          ) : (
            <div>
              {stats.needs_attention.slice(0, 5).map((det) => (
                <div
                  key={det.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "10px 0",
                    borderBottom: "1px solid var(--color-border-subtle)",
                  }}
                >
                  {/* Severity badge */}
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      textTransform: "uppercase",
                      letterSpacing: "0.4px",
                      padding: "3px 8px",
                      borderRadius: 4,
                      background: SEVERITY_BG[det.severity] || SEVERITY_BG.low,
                      color: SEVERITY_COLORS[det.severity] || SEVERITY_COLORS.low,
                      flexShrink: 0,
                      minWidth: 56,
                      textAlign: "center",
                    }}
                  >
                    {det.severity}
                  </span>

                  {/* Source */}
                  <span
                    className="hidden sm:inline truncate"
                    style={{
                      fontSize: 12,
                      color: "var(--color-text-secondary)",
                      flexShrink: 0,
                      width: 110,
                    }}
                  >
                    {det.source}
                  </span>

                  {/* Title — truncated */}
                  <span
                    style={{
                      fontSize: 13,
                      color: "var(--color-text-primary)",
                      flex: 1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {det.title}
                  </span>

                  {/* Relative time */}
                  <span
                    style={{
                      fontSize: 11,
                      color: "var(--color-text-tertiary)",
                      flexShrink: 0,
                    }}
                  >
                    {timeAgo(det.first_seen)}
                  </span>

                  {/* Ack button */}
                  <button
                    onClick={() => handleAck(det.id)}
                    disabled={ackingId === det.id}
                    style={{
                      padding: "4px 12px",
                      borderRadius: 6,
                      fontSize: 11,
                      fontWeight: 500,
                      fontFamily: "var(--font-sans)",
                      border: "1px solid var(--color-border)",
                      background: "var(--color-surface-2)",
                      color: "var(--color-text-secondary)",
                      cursor: ackingId === det.id ? "not-allowed" : "pointer",
                      opacity: ackingId === det.id ? 0.6 : 1,
                      flexShrink: 0,
                    }}
                  >
                    {ackingId === det.id ? "..." : "Ack"}
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Footer link */}
          <div style={{ marginTop: 12 }}>
            <Link
              to="/detections"
              style={{
                fontSize: 13,
                fontWeight: 500,
                color: "var(--color-accent)",
                textDecoration: "none",
              }}
            >
              View all detections &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
