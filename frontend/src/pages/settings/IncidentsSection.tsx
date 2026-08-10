import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Keyword } from "../../types";
import api from "../../api";
import { Button, Input, SectionCard } from "../../components/ui";
import { KeywordSelector } from "./KeywordSelector";
import { useIncidents, incidentsKey } from "../../queries/useIncidents";
import { useKeywords, keywordsKey } from "../../queries/useKeywords";

interface IncidentFormData {
  name: string;
  description: string;
  keyword_ids: number[];
}

interface IncidentFormProps {
  initial?: Partial<IncidentFormData>;
  availableKeywords: Keyword[];
  onSave: (data: IncidentFormData) => Promise<void>;
  onCancel: () => void;
  onKeywordCreated: (kw: Keyword) => void;
  submitLabel: string;
  submittingLabel: string;
}

// Single form component used for both create and edit modes.
function IncidentForm({
  initial,
  availableKeywords,
  onSave,
  onCancel,
  onKeywordCreated,
  submitLabel,
  submittingLabel,
}: IncidentFormProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [keywordIds, setKeywordIds] = useState<number[]>(initial?.keyword_ids ?? []);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit() {
    if (!name.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onSave({
        name: name.trim(),
        description: description.trim(),
        keyword_ids: keywordIds,
      });
    } catch {
      setError("Failed to save incident.");
    } finally {
      setSaving(false);
    }
  }

  const labelStyle: React.CSSProperties = {
    fontSize: 12,
    fontWeight: 500,
    color: "var(--color-text-secondary)",
    marginBottom: 4,
    display: "block",
  };

  return (
    <div
      style={{
        background: "var(--color-surface-0)",
        border: "1px solid var(--color-border)",
        borderRadius: 8,
        padding: 16,
        marginBottom: 12,
      }}
    >
      <div className="flex gap-3 flex-wrap" style={{ marginBottom: 12 }}>
        <div style={{ flex: "1 1 200px" }}>
          <Input
            label="Name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Q1 breach investigation"
            required
          />
        </div>
        <div style={{ flex: "2 1 300px" }}>
          <label style={labelStyle}>Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Brief description of the incident..."
            rows={2}
            style={{
              width: "100%",
              padding: "8px 12px",
              borderRadius: 8,
              fontSize: 13,
              fontFamily: "var(--font-sans)",
              background: "var(--color-surface-0)",
              border: "1px solid var(--color-border)",
              color: "var(--color-text-primary)",
              outline: "none",
              resize: "vertical",
            }}
            onFocus={(e) => {
              e.currentTarget.style.borderColor = "var(--color-accent)";
              e.currentTarget.style.boxShadow = "0 0 0 3px var(--color-accent-muted)";
            }}
            onBlur={(e) => {
              e.currentTarget.style.borderColor = "var(--color-border)";
              e.currentTarget.style.boxShadow = "none";
            }}
          />
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <label style={labelStyle}>Linked Keywords</label>
        <div style={{ marginTop: 4 }}>
          <KeywordSelector
            keywords={availableKeywords}
            selectedIds={keywordIds}
            onToggle={(id) =>
              setKeywordIds((prev) =>
                prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
              )
            }
            onSelectAll={(ids) =>
              setKeywordIds((prev) => [...new Set([...prev, ...ids])])
            }
            onDeselectAll={(ids) =>
              setKeywordIds((prev) => prev.filter((x) => !ids.includes(x)))
            }
            onKeywordCreated={(kw) => {
              onKeywordCreated(kw);
              setKeywordIds((prev) => [...prev, kw.id]);
            }}
          />
        </div>
      </div>

      <div className="flex gap-2">
        <Button
          type="button"
          onClick={handleSubmit}
          disabled={saving || !name.trim()}
        >
          {saving ? submittingLabel : submitLabel}
        </Button>
        <Button type="button" variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
      {error && (
        <p style={{ marginTop: 8, fontSize: 13, color: "var(--color-danger)" }}>{error}</p>
      )}
    </div>
  );
}

export default function IncidentsSection() {
  const queryClient = useQueryClient();
  const { data: incidents = [], isLoading: loading } = useIncidents();
  const { data: availableKeywords = [] } = useKeywords();

  const [showNew, setShowNew] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showClosed, setShowClosed] = useState(false);

  function invalidateIncidents() {
    queryClient.invalidateQueries({ queryKey: incidentsKey });
  }

  function appendKeywordToCache(kw: Keyword) {
    queryClient.setQueryData<Keyword[] | undefined>(keywordsKey, (prev) =>
      prev ? [...prev, kw] : prev
    );
  }

  async function handleCreate(data: IncidentFormData) {
    await api.post("/incidents", {
      name: data.name,
      description: data.description || null,
      keyword_ids: data.keyword_ids,
    });
    setShowNew(false);
    invalidateIncidents();
  }

  async function handleUpdate(id: number, data: IncidentFormData) {
    await api.patch(`/incidents/${id}`, {
      name: data.name,
      description: data.description || null,
      keyword_ids: data.keyword_ids,
    });
    setEditingId(null);
    invalidateIncidents();
  }

  async function handleCloseIncident(id: number) {
    try {
      await api.patch(`/incidents/${id}`, { status: "closed" });
      invalidateIncidents();
    } catch {
      // ignore
    }
  }

  async function handleReopenIncident(id: number) {
    try {
      await api.patch(`/incidents/${id}`, { status: "active" });
      invalidateIncidents();
    } catch {
      // ignore
    }
  }

  const activeIncidents = incidents.filter((i) => i.status === "active");
  const closedIncidents = incidents.filter((i) => i.status === "closed");

  return (
    <SectionCard title="Incidents">
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 16 }}>
        Group related detections under a named incident for coordinated triage and tracking.
      </p>

      {loading ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>Loading...</p>
      ) : (
        <>
          {activeIncidents.length === 0 && !showNew && (
            <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 12 }}>
              No active incidents.
            </p>
          )}

          {activeIncidents.map((inc) =>
            editingId === inc.id ? (
              <IncidentForm
                key={inc.id}
                initial={{
                  name: inc.name,
                  description: inc.description || "",
                  keyword_ids: inc.keywords.map((k) => k.id),
                }}
                availableKeywords={availableKeywords}
                onSave={(data) => handleUpdate(inc.id, data)}
                onCancel={() => setEditingId(null)}
                onKeywordCreated={appendKeywordToCache}
                submitLabel="Save"
                submittingLabel="Saving..."
              />
            ) : (
              <div
                key={inc.id}
                style={{
                  background: "var(--color-surface-0)",
                  borderRadius: 8,
                  padding: "14px 16px",
                  marginBottom: 12,
                  border: "1px solid var(--color-border)",
                  borderLeftColor: "#f59e0b",
                  borderLeftWidth: 3,
                }}
              >
                <div className="flex items-center justify-between" style={{ marginBottom: 6 }}>
                  <div className="flex items-center gap-2">
                    <span style={{ fontSize: 14, fontWeight: 600, color: "var(--color-text-primary)" }}>
                      {inc.name}
                    </span>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        padding: "2px 8px",
                        borderRadius: 4,
                        background: "rgba(245,158,11,0.15)",
                        color: "#f59e0b",
                        textTransform: "uppercase",
                        letterSpacing: "0.4px",
                      }}
                    >
                      ACTIVE
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant="secondary" onClick={() => setEditingId(inc.id)}>
                      Edit
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => handleCloseIncident(inc.id)}>
                      Close
                    </Button>
                  </div>
                </div>
                {inc.description && (
                  <p style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: 8 }}>
                    {inc.description}
                  </p>
                )}
                {inc.keywords.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {inc.keywords.map((kw) => (
                      <span
                        key={kw.id}
                        style={{
                          display: "inline-block",
                          padding: "2px 8px",
                          borderRadius: 20,
                          fontSize: 11,
                          background: "rgba(20,184,166,0.12)",
                          color: "var(--color-accent)",
                          border: "1px solid rgba(20,184,166,0.3)",
                        }}
                      >
                        {kw.term}
                      </span>
                    ))}
                  </div>
                )}
                <p style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 8 }}>
                  Created {new Date(inc.created_at).toLocaleDateString()}
                </p>
              </div>
            )
          )}

          {showNew ? (
            <IncidentForm
              availableKeywords={availableKeywords}
              onSave={handleCreate}
              onCancel={() => setShowNew(false)}
              onKeywordCreated={appendKeywordToCache}
              submitLabel="Create Incident"
              submittingLabel="Creating..."
            />
          ) : (
            <Button onClick={() => setShowNew(true)}>+ New Incident</Button>
          )}

          {closedIncidents.length > 0 && (
            <div style={{ marginTop: 20 }}>
              <button
                onClick={() => setShowClosed(!showClosed)}
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  fontSize: 12,
                  fontWeight: 500,
                  color: "var(--color-text-tertiary)",
                  padding: 0,
                  marginBottom: 8,
                }}
              >
                {showClosed ? "▾" : "▸"} Closed Incidents ({closedIncidents.length})
              </button>
              {showClosed &&
                closedIncidents.map((inc) => (
                  <div
                    key={inc.id}
                    style={{
                      background: "var(--color-surface-0)",
                      borderRadius: 8,
                      padding: "10px 14px",
                      marginBottom: 8,
                      opacity: 0.7,
                      border: "1px solid var(--color-border)",
                      borderLeftColor: "var(--color-text-tertiary)",
                      borderLeftWidth: 3,
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span style={{ fontSize: 13, fontWeight: 500, color: "var(--color-text-secondary)" }}>
                          {inc.name}
                        </span>
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 500,
                            padding: "2px 6px",
                            borderRadius: 4,
                            background: "var(--color-surface-2)",
                            color: "var(--color-text-tertiary)",
                            textTransform: "uppercase",
                          }}
                        >
                          CLOSED
                        </span>
                      </div>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleReopenIncident(inc.id)}
                      >
                        Reopen
                      </Button>
                    </div>
                    {inc.closed_at && (
                      <p style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginTop: 4 }}>
                        Closed {new Date(inc.closed_at).toLocaleDateString()}
                      </p>
                    )}
                  </div>
                ))}
            </div>
          )}
        </>
      )}
    </SectionCard>
  );
}
