import type { SourceStatus as SourceStatusType } from "../types";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../hooks/useAuth";
import SourceCard from "../components/SourceCard";
import { useSources, sourcesKey } from "../queries/useSources";

export default function SourceStatus() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const queryClient = useQueryClient();
  const { data: sources = [], isLoading, isError } = useSources();

  // SourceCard reports the updated row after the user toggles enabled. We
  // splice it into the cached array so the UI updates immediately; the next
  // 30s background refetch will reconcile against the server.
  function handleToggle(updated: SourceStatusType) {
    queryClient.setQueryData<SourceStatusType[] | undefined>(sourcesKey, (prev) =>
      prev
        ? prev.map((s) =>
            s.source_name === updated.source_name ? updated : s
          )
        : prev
    );
  }

  // Match the dashboard's definition: "healthy" means enabled AND zero
  // consecutive failures. A disabled source isn't failing — it's intentionally
  // paused, so it gets its own bucket.
  const disabled = sources.filter((s) => !s.enabled).length;
  const healthy = sources.filter((s) => s.enabled && s.consecutive_failures === 0).length;
  const degraded = sources.filter((s) => s.enabled && s.consecutive_failures > 0 && s.consecutive_failures <= 2).length;
  const failing = sources.filter((s) => s.enabled && s.consecutive_failures > 2).length;

  const summaryPill = (count: number, label: string, color: string, bg: string) => (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 10px",
        borderRadius: 4,
        fontSize: 12,
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
        }}
      />
      {count} {label}
    </span>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1
          className="text-xl font-semibold"
          style={{ color: "var(--color-text-primary)" }}
        >
          Source Status
        </h1>
        {!isLoading && (
          <div className="flex items-center gap-2">
            {healthy > 0 &&
              summaryPill(healthy, "healthy", "var(--color-success)", "rgba(52,211,153,0.12)")}
            {degraded > 0 &&
              summaryPill(degraded, "degraded", "var(--color-warning)", "rgba(251,191,36,0.12)")}
            {failing > 0 &&
              summaryPill(failing, "failing", "var(--color-danger)", "rgba(239,68,68,0.12)")}
            {disabled > 0 &&
              summaryPill(disabled, "disabled", "var(--color-text-tertiary)", "var(--color-surface-3)")}
          </div>
        )}
      </div>

      {isError && (
        <div
          style={{
            padding: "12px 16px",
            borderRadius: 6,
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.25)",
            color: "var(--color-danger)",
            fontSize: 13,
          }}
        >
          Failed to load source status.
        </div>
      )}

      {isLoading && (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>Loading sources…</p>
      )}

      {!isLoading && sources.length === 0 && !isError && (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>
          No sources configured.
        </p>
      )}

      {/* Source grid */}
      {sources.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {sources.map((source) => (
            <SourceCard
              key={source.source_name}
              source={source}
              isAdmin={isAdmin}
              onToggle={handleToggle}
            />
          ))}
        </div>
      )}
    </div>
  );
}
