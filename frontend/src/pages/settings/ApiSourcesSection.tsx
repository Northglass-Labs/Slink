import { useEffect, useState } from "react";
import api from "../../api";
import { SectionCard } from "../../components/ui";
import { StatusIndicator } from "./StatusIndicator";

interface HealthSource {
  name: string;
  enabled: boolean;
  consecutive_failures: number;
  healthy: boolean;
}

interface HealthResponse {
  status: string;
  sources: HealthSource[];
}

const rowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "10px 0",
  borderBottom: "1px solid var(--color-border-subtle)",
};

const metaLabel: React.CSSProperties = {
  fontSize: 13,
  color: "var(--color-text-secondary)",
};

export default function ApiSourcesSection() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<HealthResponse>("/health")
      .then((r) => setHealth(r.data))
      .catch(() => {
        // Failed health load — fall through to error state
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <SectionCard title="API Sources">
      {loading ? (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>Loading…</p>
      ) : health ? (
        <div>
          {health.sources.length === 0 ? (
            <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>
              No collectors configured.
            </p>
          ) : (
            health.sources.map((src, idx) => (
              <div
                key={src.name}
                style={{
                  ...rowStyle,
                  borderBottom:
                    idx === health.sources.length - 1
                      ? "none"
                      : "1px solid var(--color-border-subtle)",
                }}
              >
                <div>
                  <span style={metaLabel}>
                    {src.name
                      .split("_")
                      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                      .join(" ")}
                  </span>
                  {!src.enabled && (
                    <span
                      style={{
                        marginLeft: 8,
                        fontSize: 10,
                        color: "var(--color-text-tertiary)",
                      }}
                    >
                      (disabled)
                    </span>
                  )}
                </div>
                <StatusIndicator
                  ok={src.healthy}
                  okLabel="Healthy"
                  failLabel={`${src.consecutive_failures} failure${
                    src.consecutive_failures !== 1 ? "s" : ""
                  }`}
                />
              </div>
            ))
          )}
        </div>
      ) : (
        <p style={{ color: "var(--color-danger)", fontSize: 13 }}>
          Failed to load source health.
        </p>
      )}
    </SectionCard>
  );
}
