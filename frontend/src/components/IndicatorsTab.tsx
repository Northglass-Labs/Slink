import { useEffect, useState } from "react";
import type { Indicator } from "../types";
import api from "../api";

interface Props {
  detectionId: number;
  onCountChange?: (count: number) => void;
}

// Color mapping for indicator type badges
const TYPE_COLORS: Record<string, { bg: string; color: string; border: string }> = {
  hash_md5: { bg: "rgba(251,146,60,0.12)", color: "#fb923c", border: "rgba(251,146,60,0.3)" },
  hash_sha1: { bg: "rgba(251,146,60,0.12)", color: "#fb923c", border: "rgba(251,146,60,0.3)" },
  hash_sha256: { bg: "rgba(251,146,60,0.12)", color: "#fb923c", border: "rgba(251,146,60,0.3)" },
  domain: { bg: "rgba(96,165,250,0.12)", color: "#60a5fa", border: "rgba(96,165,250,0.3)" },
  url: { bg: "rgba(96,165,250,0.12)", color: "#60a5fa", border: "rgba(96,165,250,0.3)" },
  ipv4: { bg: "rgba(167,139,250,0.12)", color: "#a78bfa", border: "rgba(167,139,250,0.3)" },
  cve: { bg: "rgba(244,114,182,0.12)", color: "#f472b6", border: "rgba(244,114,182,0.3)" },
  mitre_technique: { bg: "rgba(45,212,191,0.12)", color: "#2dd4bf", border: "rgba(45,212,191,0.3)" },
  malware_family: { bg: "rgba(251,191,36,0.12)", color: "#fbbf24", border: "rgba(251,191,36,0.3)" },
  email: { bg: "rgba(156,163,175,0.12)", color: "#9ca3af", border: "rgba(156,163,175,0.3)" },
};

const DEFAULT_COLOR = { bg: "rgba(156,163,175,0.12)", color: "#9ca3af", border: "rgba(156,163,175,0.3)" };

// Build external lookup URL and label based on indicator type
function getLookup(type: string, value: string): { url: string; label: string } | null {
  switch (type) {
    case "hash_md5":
    case "hash_sha1":
    case "hash_sha256":
      return { url: `https://www.virustotal.com/gui/search/${value}`, label: "VirusTotal" };
    case "domain":
    case "url":
      return { url: `https://www.shodan.io/search?query=${value}`, label: "Shodan" };
    case "ipv4":
      return { url: `https://www.shodan.io/search?query=${value}`, label: "Shodan" };
    case "cve":
      return { url: `https://nvd.nist.gov/vuln/detail/${value}`, label: "NVD" };
    case "mitre_technique":
      return { url: `https://attack.mitre.org/techniques/${value}/`, label: "ATT&CK" };
    case "malware_family":
      return { url: `https://malpedia.caad.fkie.fraunhofer.de/search?q=${value}`, label: "Malpedia" };
    default:
      return null;
  }
}

export default function IndicatorsTab({ detectionId, onCountChange }: Props) {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchIndicators() {
      setLoading(true);
      setError(null);
      try {
        const res = await api.get<Indicator[]>(`/detections/${detectionId}/indicators`);
        if (!cancelled) {
          setIndicators(res.data);
          onCountChange?.(res.data.length);
        }
      } catch {
        if (!cancelled) setError("Failed to load indicators.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchIndicators();
    return () => { cancelled = true; };
  }, [detectionId, onCountChange]);

  if (loading) {
    return (
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", padding: "12px 0" }}>
        Loading indicators...
      </p>
    );
  }

  if (error) {
    return (
      <p style={{ fontSize: 13, color: "var(--color-danger)", padding: "12px 0" }}>{error}</p>
    );
  }

  if (indicators.length === 0) {
    return (
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", fontStyle: "italic", padding: "12px 0" }}>
        No indicators extracted
      </p>
    );
  }

  const tableHeader: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
    color: "var(--color-text-tertiary)",
    padding: "8px 12px",
    textAlign: "left",
    borderBottom: "1px solid var(--color-border)",
  };

  const tableCell: React.CSSProperties = {
    fontSize: 13,
    padding: "8px 12px",
    color: "var(--color-text-primary)",
    borderBottom: "1px solid var(--color-border)",
  };

  return (
    <div style={{ overflowX: "auto" }}>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          background: "var(--color-surface-0)",
          border: "1px solid var(--color-border)",
          borderRadius: 6,
        }}
      >
        <thead>
          <tr>
            <th style={tableHeader}>Type</th>
            <th style={tableHeader}>Value</th>
            <th style={tableHeader}>Lookup</th>
          </tr>
        </thead>
        <tbody>
          {indicators.map((indicator) => {
            const colors = TYPE_COLORS[indicator.type] ?? DEFAULT_COLOR;
            const lookup = getLookup(indicator.type, indicator.value);

            return (
              <tr key={indicator.id}>
                <td style={tableCell}>
                  <span
                    style={{
                      display: "inline-block",
                      padding: "2px 8px",
                      borderRadius: 12,
                      fontSize: 11,
                      fontWeight: 500,
                      background: colors.bg,
                      color: colors.color,
                      border: `1px solid ${colors.border}`,
                      whiteSpace: "nowrap",
                    }}
                  >
                    {indicator.type}
                  </span>
                </td>
                <td style={{ ...tableCell, fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" }}>
                  {indicator.value}
                </td>
                <td style={tableCell}>
                  {lookup ? (
                    <a
                      href={lookup.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 4,
                        fontSize: 12,
                        fontWeight: 500,
                        color: "var(--color-accent)",
                        textDecoration: "none",
                      }}
                    >
                      {lookup.label}
                      <svg width="10" height="10" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M10 7v3H2V3h3M7 2h3v3M5.5 6.5 10 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </a>
                  ) : (
                    <span style={{ fontSize: 12, color: "var(--color-text-tertiary)" }}>--</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
