import { useCallback, useEffect, useState } from "react";
import api from "../../api";
import { Button, SectionCard } from "../../components/ui";

interface AuditLogEntry {
  id: number;
  user_id: number | null;
  username: string;
  action: string;
  target_type: string;
  target_id: number | null;
  detail: Record<string, unknown> | null;
  created_at: string;
}

interface AuditLogListResponse {
  items: AuditLogEntry[];
  total: number;
}

const AUDIT_LIMIT = 20;

export default function AuditLogSection() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);

  const loadLogs = useCallback(async (newOffset: number) => {
    setLoading(true);
    try {
      const r = await api.get<AuditLogListResponse>("/audit", {
        params: { limit: AUDIT_LIMIT, offset: newOffset },
      });
      setLogs(r.data.items);
      setTotal(r.data.total);
    } catch {
      // silently fail — only admins see this section
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadLogs(0);
  }, [loadLogs]);

  return (
    <SectionCard title="Audit Log">
      {loading && logs.length === 0 ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>Loading audit log...</p>
      ) : logs.length === 0 ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>No audit events yet.</p>
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: 12,
                fontFamily: "var(--font-sans)",
              }}
            >
              <thead>
                <tr style={{ borderBottom: "1px solid var(--color-border)", textAlign: "left" }}>
                  <th
                    style={{
                      padding: "6px 8px",
                      color: "var(--color-text-secondary)",
                      fontWeight: 500,
                      whiteSpace: "nowrap",
                    }}
                  >
                    When
                  </th>
                  <th style={{ padding: "6px 8px", color: "var(--color-text-secondary)", fontWeight: 500 }}>
                    User
                  </th>
                  <th style={{ padding: "6px 8px", color: "var(--color-text-secondary)", fontWeight: 500 }}>
                    Action
                  </th>
                  <th style={{ padding: "6px 8px", color: "var(--color-text-secondary)", fontWeight: 500 }}>
                    Target
                  </th>
                  <th style={{ padding: "6px 8px", color: "var(--color-text-secondary)", fontWeight: 500 }}>
                    Detail
                  </th>
                </tr>
              </thead>
              <tbody>
                {logs.map((entry) => {
                  const ago = (() => {
                    const diff = Date.now() - new Date(entry.created_at).getTime();
                    const mins = Math.floor(diff / 60000);
                    if (mins < 1) return "just now";
                    if (mins < 60) return `${mins}m ago`;
                    const hrs = Math.floor(mins / 60);
                    if (hrs < 24) return `${hrs}h ago`;
                    const days = Math.floor(hrs / 24);
                    return `${days}d ago`;
                  })();

                  const detailSummary = entry.detail
                    ? Object.entries(entry.detail)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(", ")
                    : "";

                  return (
                    <tr
                      key={entry.id}
                      style={{ borderBottom: "1px solid var(--color-border-subtle)" }}
                    >
                      <td
                        style={{
                          padding: "6px 8px",
                          color: "var(--color-text-tertiary)",
                          whiteSpace: "nowrap",
                        }}
                        title={new Date(entry.created_at).toLocaleString()}
                      >
                        {ago}
                      </td>
                      <td
                        style={{
                          padding: "6px 8px",
                          color: "var(--color-text-primary)",
                          fontWeight: 500,
                        }}
                      >
                        {entry.username}
                      </td>
                      <td style={{ padding: "6px 8px", color: "var(--color-text-primary)" }}>
                        <code
                          style={{
                            fontSize: 11,
                            padding: "2px 6px",
                            borderRadius: 4,
                            background: "var(--color-surface-2)",
                            color: "var(--color-text-secondary)",
                          }}
                        >
                          {entry.action}
                        </code>
                      </td>
                      <td
                        style={{
                          padding: "6px 8px",
                          color: "var(--color-text-secondary)",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {entry.target_type}
                        {entry.target_id != null && (
                          <span style={{ color: "var(--color-text-tertiary)" }}>
                            {" "}
                            #{entry.target_id}
                          </span>
                        )}
                      </td>
                      <td
                        style={{
                          padding: "6px 8px",
                          color: "var(--color-text-tertiary)",
                          maxWidth: 260,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={detailSummary}
                      >
                        {detailSummary || "\u2014"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {total > AUDIT_LIMIT && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginTop: 12,
                fontSize: 12,
                color: "var(--color-text-tertiary)",
              }}
            >
              <span>
                Showing {offset + 1}–{Math.min(offset + AUDIT_LIMIT, total)} of {total}
              </span>
              <div style={{ display: "flex", gap: 6 }}>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={offset === 0 || loading}
                  onClick={() => {
                    const newOffset = Math.max(0, offset - AUDIT_LIMIT);
                    setOffset(newOffset);
                    loadLogs(newOffset);
                  }}
                >
                  Prev
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  disabled={offset + AUDIT_LIMIT >= total || loading}
                  onClick={() => {
                    const newOffset = offset + AUDIT_LIMIT;
                    setOffset(newOffset);
                    loadLogs(newOffset);
                  }}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </SectionCard>
  );
}
