import { useCallback, useEffect, useState } from "react";
import type { Detection, Incident } from "../types";
import api from "../api";
import { useAuth } from "../hooks/useAuth";
import IndicatorsTab from "./IndicatorsTab";
import NotesTab from "./NotesTab";

interface Props {
  detection: Detection;
  onStatusChange: (id: number, status: Detection["status"]) => void;
}

// Maps a source name to its investigation dashboard URL.
// Used when the detection has no source_url of its own.
// Falcon links use the us-1 region (CrowdStrike's doc default); on another
// cloud (us-2 / eu-1 / us-gov-1) swap the subdomain to match your tenant.
const SOURCE_DASHBOARDS: Record<string, string> = {
  crowdstrike_recon: "https://falcon.us-1.crowdstrike.com/intelligence-v2/recon",
  ransomwatch: "https://ransomware.live",
  ransomlook: "https://www.ransomlook.io/recent",
  alienvault_otx: "https://otx.alienvault.com/dashboard",
  crowdstrike_intel: "https://falcon.us-1.crowdstrike.com/intelligence-v2/reports",
};

const SOURCE_LABELS: Record<string, string> = {
  ransomwatch: "RansomWatch",
  ransomlook: "Ransomlook",
  cisa_kev: "CISA KEV",
  threatfox: "ThreatFox",
  urlhaus: "URLhaus",
  malwarebazaar: "MalwareBazaar",
  feodo_tracker: "Feodo Tracker",
  alienvault_otx: "OTX Dashboard",
  nvd: "NVD",
  github_advisory: "GitHub Advisories",
  crowdstrike_recon: "Falcon Recon",
  crowdstrike_intel: "Falcon Intel",
};

// Escalate is styled differently from the other actions — it's a destructive
// escalation step, so it gets a solid red treatment to stand out.
const statusActions: { label: string; value: Detection["status"]; bg: string; color: string; border: string }[] = [
  {
    label: "Acknowledge",
    value: "acknowledged",
    bg: "rgba(96,165,250,0.12)",
    color: "var(--color-info)",
    border: "rgba(96,165,250,0.3)",
  },
  {
    label: "Dismiss",
    value: "dismissed",
    bg: "var(--color-surface-3)",
    color: "var(--color-text-secondary)",
    border: "var(--color-border)",
  },
];

type Tab = "investigate" | "ai" | "indicators" | "notes" | "raw";

interface AISummary {
  cached: boolean;
  summary: string;
  attack_techniques: { id: string; name: string }[];
  pivots: { value: string; kind: string }[];
  generated_at: string;
  model?: string;
}

export default function DetectionDetail({ detection, onStatusChange }: Props) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [updating, setUpdating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Toast message shown after escalation
  const [toast, setToast] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("investigate");
  const [indicatorCount, setIndicatorCount] = useState<number | null>(null);
  const [noteCount, setNoteCount] = useState<number | null>(null);
  const [linkedIncidents, setLinkedIncidents] = useState<Incident[]>([]);
  // Raw JSON is not returned in list responses (intentional — it may be
  // large and admin-only). We lazy-fetch the full detection when an admin
  // opens the Raw tab. "loaded" is true after the fetch resolves even if
  // the server returned null (viewer role, or row genuinely has no data).
  const [rawData, setRawData] = useState<Record<string, unknown> | null | undefined>(
    detection.raw_data
  );
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);
  const [aiSummary, setAiSummary] = useState<AISummary | null | undefined>(undefined);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const fetchAiSummary = useCallback((refresh = false) => {
    setAiLoading(true);
    setAiError(null);
    api
      .post<AISummary>(
        `/detections/${detection.id}/ai-summary${refresh ? "?refresh=true" : ""}`,
      )
      .then((r) => setAiSummary(r.data))
      .catch((err) => {
        const status = err?.response?.status;
        if (status === 503) setAiError("AI summary disabled — set ANTHROPIC_API_KEY to enable.");
        else if (status === 502) setAiError("Upstream model call failed. Try again in a moment.");
        else setAiError("Failed to load AI summary.");
      })
      .finally(() => setAiLoading(false));
  }, [detection.id]);

  useEffect(() => {
    if (activeTab !== "ai") return;
    if (aiSummary !== undefined) return;
    if (aiLoading) return;
    fetchAiSummary(false);
  }, [activeTab, aiSummary, aiLoading, fetchAiSummary]);

  // Fetch active incidents and check for keyword overlap with this detection
  useEffect(() => {
    api.get<Incident[]>("/incidents")
      .then((r) => {
        const active = r.data.filter((i) => i.status === "active");
        const matched = active.filter((inc) =>
          inc.keywords.some((kw) =>
            detection.matched_keywords.includes(kw.term)
          )
        );
        setLinkedIncidents(matched);
      })
      .catch(() => {});
  }, [detection.id, detection.matched_keywords]);

  // Fetch the full detection (including raw_data) the first time an admin
  // activates the Raw tab. Cached in component state so tab switches are cheap.
  useEffect(() => {
    if (activeTab !== "raw" || !isAdmin) return;
    if (rawData !== undefined) return;
    if (rawLoading) return;
    setRawLoading(true);
    setRawError(null);
    api
      .get<Detection>(`/detections/${detection.id}`)
      .then((r) => setRawData(r.data.raw_data ?? null))
      .catch(() => setRawError("Failed to load raw data."))
      .finally(() => setRawLoading(false));
  }, [activeTab, isAdmin, detection.id, rawData, rawLoading]);

  const handleIndicatorCountChange = useCallback((count: number) => {
    setIndicatorCount(count);
  }, []);

  const handleNoteCountChange = useCallback((count: number) => {
    setNoteCount(count);
  }, []);

  async function updateStatus(status: Detection["status"]) {
    setUpdating(true);
    setError(null);
    try {
      await api.patch(`/detections/${detection.id}/status`, { status });
      onStatusChange(detection.id, status);
      if (status === "escalated") {
        setToast("Detection escalated — notify your IR team");
        setTimeout(() => setToast(null), 4000);
      }
    } catch {
      setError("Failed to update status.");
    } finally {
      setUpdating(false);
    }
  }

  const fieldLabel: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 500,
    textTransform: "uppercase",
    letterSpacing: "0.5px",
    color: "var(--color-text-tertiary)",
  };

  const fieldValue: React.CSSProperties = {
    fontSize: 13,
    color: "var(--color-text-primary)",
    marginTop: 3,
  };

  // Determine the investigation link: prefer the detection's own source_url,
  // fall back to the known dashboard for the source.
  const investigateDashboardUrl = SOURCE_DASHBOARDS[detection.source];
  const investigateLabel = SOURCE_LABELS[detection.source] ?? detection.source;

  return (
    <tr>
      <td
        colSpan={7}
        style={{
          backgroundColor: "var(--color-surface-1)",
          borderTop: "1px solid var(--color-border)",
          borderBottom: "1px solid var(--color-border)",
          padding: "16px 24px",
        }}
      >
        <div className="space-y-4">
          {/* Tab bar */}
          <div
            style={{
              display: "flex",
              gap: 0,
              borderBottom: "1px solid var(--color-border)",
              marginBottom: 4,
            }}
          >
            {([
              { id: "investigate" as Tab, label: "Investigate" },
              { id: "ai" as Tab, label: "AI Summary" },
              { id: "indicators" as Tab, label: indicatorCount !== null ? `Indicators (${indicatorCount})` : "Indicators" },
              { id: "notes" as Tab, label: noteCount !== null ? `Notes (${noteCount})` : "Notes" },
              // Show the Raw tab unconditionally for admins — raw_data is
              // lazy-loaded on activation so we don't ship it in list payloads.
              ...(isAdmin ? [{ id: "raw" as Tab, label: "Raw JSON" }] : []),
            ]).map((tab) => (
              <button
                key={tab.id}
                onClick={(e) => {
                  e.stopPropagation();
                  setActiveTab(tab.id);
                }}
                style={{
                  padding: "8px 16px",
                  fontSize: 12,
                  fontWeight: activeTab === tab.id ? 600 : 400,
                  fontFamily: "var(--font-sans)",
                  color: activeTab === tab.id ? "var(--color-accent)" : "var(--color-text-secondary)",
                  background: "transparent",
                  border: "none",
                  borderBottom: activeTab === tab.id
                    ? "2px solid var(--color-accent)"
                    : "2px solid transparent",
                  cursor: "pointer",
                  transition: "color 120ms ease, border-color 120ms ease",
                  marginBottom: -1,
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content: Investigate */}
          {activeTab === "investigate" && (
            <>
              {/* Core fields */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p style={fieldLabel}>ID</p>
                  <p style={fieldValue}>{detection.id}</p>
                </div>
                <div>
                  <p style={fieldLabel}>Status</p>
                  <p style={{ ...fieldValue, textTransform: "capitalize" }}>{detection.status}</p>
                </div>
                <div>
                  <p style={fieldLabel}>First Seen</p>
                  <p style={fieldValue}>{new Date(detection.first_seen).toLocaleString()}</p>
                </div>
                <div>
                  <p style={fieldLabel}>Last Seen</p>
                  <p style={fieldValue}>{new Date(detection.last_seen).toLocaleString()}</p>
                </div>

                {/* Linked incident badges */}
                {linkedIncidents.length > 0 && (
                  <div className="col-span-2">
                    <p style={fieldLabel}>Linked Incidents</p>
                    <div className="flex flex-wrap gap-2" style={{ marginTop: 3 }}>
                      {linkedIncidents.map((inc) => (
                        <span
                          key={inc.id}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 5,
                            padding: "4px 10px",
                            borderRadius: 6,
                            fontSize: 12,
                            fontWeight: 500,
                            background: "rgba(245,158,11,0.12)",
                            color: "#f59e0b",
                            border: "1px solid rgba(245,158,11,0.3)",
                          }}
                        >
                          <span
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              background: "#f59e0b",
                              flexShrink: 0,
                            }}
                          />
                          {inc.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Source URL — clickable if present; otherwise show contextual investigate link */}
                <div className="col-span-2">
                  <p style={fieldLabel}>Source URL</p>
                  <p style={{ marginTop: 3 }}>
                    {detection.source_url ? (
                      <a
                        href={detection.source_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: "var(--color-accent)", fontSize: 13, wordBreak: "break-all" }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {detection.source_url}
                      </a>
                    ) : (
                      <span style={{ fontSize: 13, color: "var(--color-text-tertiary)", fontStyle: "italic" }}>
                        No direct URL for this detection
                      </span>
                    )}
                  </p>
                </div>

                <div className="col-span-2">
                  <p style={fieldLabel}>Snippet</p>
                  <p
                    style={{
                      ...fieldValue,
                      lineHeight: 1.6,
                      color: "var(--color-text-secondary)",
                    }}
                  >
                    {detection.snippet}
                  </p>
                </div>
              </div>

              {/* Investigate section — accent pill buttons for dashboard links */}
              <div>
                <p style={{ ...fieldLabel, marginBottom: 8 }}>Investigate</p>
                <div className="flex items-center gap-2 flex-wrap">
                  {/* If the detection has its own source URL, always show it first */}
                  {detection.source_url && (
                    <a
                      href={detection.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 5,
                        padding: "5px 12px",
                        borderRadius: 20,
                        fontSize: 12,
                        fontWeight: 500,
                        background: "var(--color-accent-muted)",
                        color: "var(--color-accent)",
                        border: "1px solid var(--color-border-bright)",
                        textDecoration: "none",
                        cursor: "pointer",
                      }}
                    >
                      {/* External link icon */}
                      <svg width="11" height="11" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M10 7v3H2V3h3M7 2h3v3M5.5 6.5 10 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                      Source
                    </a>
                  )}

                  {/* Dashboard fallback link for the source */}
                  {investigateDashboardUrl && (
                    <a
                      href={investigateDashboardUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 5,
                        padding: "5px 12px",
                        borderRadius: 20,
                        fontSize: 12,
                        fontWeight: 500,
                        background: "var(--color-accent-muted)",
                        color: "var(--color-accent)",
                        border: "1px solid var(--color-border-bright)",
                        textDecoration: "none",
                        cursor: "pointer",
                      }}
                    >
                      <svg width="11" height="11" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M10 7v3H2V3h3M7 2h3v3M5.5 6.5 10 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                      {investigateLabel}
                    </a>
                  )}
                </div>
              </div>

              {/* Status action buttons */}
              <div className="flex items-center gap-3 flex-wrap">
                {statusActions.map(({ label, value, bg, color, border }) => (
                  <button
                    key={value}
                    onClick={(e) => {
                      e.stopPropagation();
                      updateStatus(value);
                    }}
                    disabled={updating || detection.status === value}
                    style={{
                      padding: "6px 14px",
                      borderRadius: 6,
                      fontSize: 12,
                      fontWeight: 500,
                      fontFamily: "var(--font-sans)",
                      background: bg,
                      color,
                      border: `1px solid ${border}`,
                      cursor: updating || detection.status === value ? "not-allowed" : "pointer",
                      opacity: updating || detection.status === value ? 0.5 : 1,
                      transition: "opacity 120ms ease",
                    }}
                  >
                    {label}
                  </button>
                ))}

                {/* Escalate — visually distinct red button to signal severity */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    updateStatus("escalated");
                  }}
                  disabled={updating || detection.status === "escalated"}
                  style={{
                    padding: "7px 18px",
                    borderRadius: 6,
                    fontSize: 12,
                    fontWeight: 700,
                    fontFamily: "var(--font-sans)",
                    background: detection.status === "escalated"
                      ? "rgba(239,68,68,0.08)"
                      : "rgba(239,68,68,0.85)",
                    color: detection.status === "escalated"
                      ? "var(--color-danger)"
                      : "#fff",
                    border: "1px solid rgba(239,68,68,0.6)",
                    cursor: updating || detection.status === "escalated" ? "not-allowed" : "pointer",
                    opacity: updating || detection.status === "escalated" ? 0.55 : 1,
                    transition: "opacity 120ms ease, background 120ms ease",
                    letterSpacing: "0.3px",
                  }}
                >
                  {detection.status === "escalated" ? "Escalated" : "Escalate"}
                </button>

                {/* Re-open — returns detection to "new" from acknowledged/dismissed/escalated */}
                {(detection.status === "acknowledged" || detection.status === "dismissed" || detection.status === "escalated") && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      updateStatus("new");
                    }}
                    disabled={updating}
                    style={{
                      padding: "6px 14px",
                      borderRadius: 6,
                      fontSize: 12,
                      fontWeight: 500,
                      fontFamily: "var(--font-sans)",
                      background: "rgba(251,191,36,0.12)",
                      color: "var(--color-warning)",
                      border: "1px solid rgba(251,191,36,0.3)",
                      cursor: updating ? "not-allowed" : "pointer",
                      opacity: updating ? 0.5 : 1,
                      transition: "opacity 120ms ease",
                    }}
                  >
                    Re-open
                  </button>
                )}

                {error && (
                  <span style={{ fontSize: 13, color: "var(--color-danger)" }}>{error}</span>
                )}

                {/* Escalation confirmation toast */}
                {toast && (
                  <span
                    style={{
                      fontSize: 12,
                      fontWeight: 500,
                      color: "#fff",
                      background: "rgba(239,68,68,0.85)",
                      padding: "5px 12px",
                      borderRadius: 6,
                      border: "1px solid rgba(239,68,68,0.5)",
                      animation: "fadeIn 150ms ease",
                    }}
                  >
                    {toast}
                  </span>
                )}
              </div>
            </>
          )}

          {/* Tab content: AI Summary */}
          {activeTab === "ai" && (
            <div style={{ fontSize: 13, lineHeight: 1.55 }}>
              {aiLoading && (
                <div style={{ color: "var(--color-text-tertiary)" }}>Asking Claude Haiku for a summary…</div>
              )}
              {aiError && <div style={{ color: "var(--color-danger)" }}>{aiError}</div>}
              {!aiLoading && !aiError && aiSummary && (
                <>
                  <div style={{ marginBottom: 18 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-text-tertiary)", marginBottom: 6 }}>Summary</div>
                    <p style={{ margin: 0, color: "var(--color-text-primary)" }}>{aiSummary.summary || "(empty)"}</p>
                  </div>
                  {aiSummary.attack_techniques.length > 0 && (
                    <div style={{ marginBottom: 18 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-text-tertiary)", marginBottom: 6 }}>MITRE ATT&amp;CK</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {aiSummary.attack_techniques.map((t) => (
                          <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noreferrer" style={{ fontSize: 12, padding: "3px 10px", borderRadius: 20, border: "1px solid var(--color-border-bright)", background: "var(--color-surface-2)", color: "var(--color-accent)", textDecoration: "none" }}>
                            {t.id} · {t.name}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                  {aiSummary.pivots.length > 0 && (
                    <div style={{ marginBottom: 18 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--color-text-tertiary)", marginBottom: 6 }}>Pivot on</div>
                      <ul style={{ margin: 0, paddingLeft: 16, color: "var(--color-text-secondary)" }}>
                        {aiSummary.pivots.map((p, i) => (
                          <li key={i} style={{ marginBottom: 2 }}>
                            <code style={{ fontSize: 12, color: "var(--color-text-primary)", fontFamily: "var(--font-mono)" }}>{p.value}</code>
                            <span style={{ marginLeft: 6, fontSize: 11, color: "var(--color-text-tertiary)" }}>({p.kind})</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid var(--color-border-subtle)", paddingTop: 10, fontSize: 11, color: "var(--color-text-tertiary)" }}>
                    <span>
                      {aiSummary.cached ? "Cached" : "Just generated"}
                      {aiSummary.model ? ` · ${aiSummary.model}` : ""}
                      {aiSummary.generated_at ? ` · ${new Date(aiSummary.generated_at).toLocaleString()}` : ""}
                    </span>
                    <button onClick={() => fetchAiSummary(true)} disabled={aiLoading} style={{ padding: "3px 10px", fontSize: 11, fontFamily: "var(--font-sans)", background: "var(--color-surface-2)", color: "var(--color-text-secondary)", border: "1px solid var(--color-border)", borderRadius: 4, cursor: aiLoading ? "not-allowed" : "pointer" }}>
                      Regenerate
                    </button>
                  </div>
                </>
              )}
            </div>
          )}

          {/* Tab content: Indicators */}
          {activeTab === "indicators" && (
            <IndicatorsTab detectionId={detection.id} onCountChange={handleIndicatorCountChange} />
          )}

          {/* Tab content: Notes */}
          {activeTab === "notes" && (
            <NotesTab detectionId={detection.id} onCountChange={handleNoteCountChange} />
          )}

          {/* Tab content: Raw JSON — admin only, lazy-fetched */}
          {activeTab === "raw" && isAdmin && (
            <div>
              {rawLoading && (
                <div style={{ fontSize: 12, color: "var(--color-text-tertiary)" }}>
                  Loading raw data…
                </div>
              )}
              {rawError && (
                <div style={{ fontSize: 12, color: "var(--color-danger)" }}>{rawError}</div>
              )}
              {!rawLoading && !rawError && rawData === null && (
                <div style={{ fontSize: 12, color: "var(--color-text-tertiary)" }}>
                  No raw data captured for this detection.
                </div>
              )}
              {!rawLoading && !rawError && rawData && (
                <pre
                  style={{
                    padding: "12px",
                    borderRadius: 6,
                    fontSize: 11,
                    fontFamily: "var(--font-mono)",
                    background: "var(--color-surface-0)",
                    border: "1px solid var(--color-border)",
                    color: "var(--color-accent)",
                    overflowX: "auto",
                    maxHeight: 360,
                  }}
                >
                  {JSON.stringify(rawData, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}
