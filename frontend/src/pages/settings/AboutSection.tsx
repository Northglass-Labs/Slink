import { useEffect, useState } from "react";
import api from "../../api";
import { useAuth } from "../../hooks/useAuth";
import { SectionCard } from "../../components/ui";

interface DetectionListResponse {
  items: { id: number }[];
  total: number;
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

const metaValue: React.CSSProperties = {
  fontSize: 13,
  fontWeight: 500,
  color: "var(--color-text-primary)",
};

export default function AboutSection() {
  const { user } = useAuth();
  const [totalDetections, setTotalDetections] = useState<number | null>(null);

  useEffect(() => {
    api
      .get<DetectionListResponse>("/detections", { params: { limit: 1, offset: 0 } })
      .then((r) => setTotalDetections(r.data.total))
      .catch(() => {
        // ignore — display em-dash
      });
  }, []);

  return (
    <SectionCard title="About">
      <div>
        <div style={rowStyle}>
          <span style={metaLabel}>Application</span>
          <span style={metaValue}>Slink</span>
        </div>
        <div style={rowStyle}>
          <span style={metaLabel}>Description</span>
          <span style={{ ...metaValue, color: "var(--color-text-secondary)" }}>
            Dark web &amp; threat intelligence monitor
          </span>
        </div>
        <div style={rowStyle}>
          <span style={metaLabel}>Total Detections</span>
          <span style={metaValue}>
            {totalDetections !== null ? totalDetections.toLocaleString() : "—"}
          </span>
        </div>
        <div style={rowStyle}>
          <span style={metaLabel}>Logged in as</span>
          <span style={metaValue}>
            {user?.username}{" "}
            <span
              style={{
                fontSize: 10,
                padding: "2px 6px",
                borderRadius: 4,
                background: "var(--color-accent-muted)",
                color: "var(--color-accent)",
                marginLeft: 4,
                textTransform: "uppercase",
                letterSpacing: "0.4px",
              }}
            >
              {user?.role}
            </span>
          </span>
        </div>
        <div style={{ ...rowStyle, borderBottom: "none" }}>
          <span style={metaLabel}>Backend</span>
          <span style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>
            FastAPI · PostgreSQL · Docker
          </span>
        </div>
      </div>
    </SectionCard>
  );
}
