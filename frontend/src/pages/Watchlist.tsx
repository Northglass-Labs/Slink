import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Keyword } from "../types";
import api from "../api";
import { useAuth } from "../hooks/useAuth";
import KeywordForm from "../components/KeywordForm";
import { useKeywords, keywordsKey } from "../queries/useKeywords";
import { useIncidents } from "../queries/useIncidents";

export default function Watchlist() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();

  const { data: keywords = [], isLoading: keywordsLoading, isError: keywordsError } = useKeywords();
  const { data: incidents = [] } = useIncidents();

  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editingKeyword, setEditingKeyword] = useState<Keyword | undefined>(undefined);

  function updateCache(updater: (prev: Keyword[]) => Keyword[]) {
    queryClient.setQueryData<Keyword[] | undefined>(keywordsKey, (prev) =>
      prev ? updater(prev) : prev
    );
  }

  async function handleToggleEnabled(keyword: Keyword) {
    try {
      const res = await api.put<Keyword>(`/keywords/${keyword.id}`, {
        term: keyword.term,
        category: keyword.category,
        enabled: !keyword.enabled,
      });
      updateCache((prev) => prev.map((k) => (k.id === keyword.id ? res.data : k)));
    } catch {
      // Silently fail — next refetch will correct the state
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this keyword?")) return;
    try {
      await api.delete(`/keywords/${id}`);
      updateCache((prev) => prev.filter((k) => k.id !== id));
    } catch {
      setError("Failed to delete keyword.");
    }
  }

  function handleSave(saved: Keyword) {
    updateCache((prev) => {
      const exists = prev.find((k) => k.id === saved.id);
      if (exists) return prev.map((k) => (k.id === saved.id ? saved : k));
      return [...prev, saved];
    });
    setShowForm(false);
    setEditingKeyword(undefined);
  }

  function openAddForm() {
    setEditingKeyword(undefined);
    setShowForm(true);
  }

  function openEditForm(keyword: Keyword) {
    setEditingKeyword(keyword);
    setShowForm(true);
  }

  function closeForm() {
    setShowForm(false);
    setEditingKeyword(undefined);
  }

  // Build a lookup: keyword ID → linked active incident names
  function getLinkedIncidents(kwId: number): string[] {
    return incidents
      .filter((inc) => inc.status === "active" && inc.keywords.some((k) => k.id === kwId))
      .map((inc) => inc.name);
  }

  // Group keywords by category — brand/threat_actor come first
  const grouped = keywords.reduce<Record<string, Keyword[]>>((acc, kw) => {
    if (!acc[kw.category]) acc[kw.category] = [];
    acc[kw.category].push(kw);
    return acc;
  }, {});

  const categoryOrder = ["brand", "threat_actor"];
  const sortedCategories = [
    ...categoryOrder.filter((c) => grouped[c]),
    ...Object.keys(grouped)
      .filter((c) => !categoryOrder.includes(c))
      .sort(),
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1
          className="text-xl font-semibold"
          style={{ color: "var(--color-text-primary)" }}
        >
          Watchlist
        </h1>
        {isAdmin && (
          <button
            onClick={openAddForm}
            style={{
              padding: "7px 14px",
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 500,
              fontFamily: "var(--font-sans)",
              background: "var(--color-accent)",
              color: "var(--color-text-inverse)",
              border: "none",
              cursor: "pointer",
              boxShadow: "0 2px 8px var(--color-accent-glow)",
              transition: "opacity 120ms ease",
            }}
          >
            + Add Keyword
          </button>
        )}
      </div>

      {(error || keywordsError) && (
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
          {error || "Failed to load keywords."}
        </div>
      )}

      {keywordsLoading && (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>Loading keywords…</p>
      )}

      {!keywordsLoading && keywords.length === 0 && !keywordsError && (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>
          No keywords configured.
        </p>
      )}

      {/* Keyword groups */}
      {sortedCategories.map((cat) => (
        <div key={cat} className="space-y-2">
          {/* Category header */}
          <div className="flex items-center gap-2">
            <span
              style={{
                fontSize: 11,
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: "0.7px",
                color: "var(--color-text-tertiary)",
              }}
            >
              {cat}
            </span>
            <span style={{ fontSize: 12, color: "var(--color-text-tertiary)" }}>
              ({grouped[cat].length})
            </span>
          </div>

          {/* Keyword table */}
          <div
            style={{
              borderRadius: 8,
              border: "1px solid var(--color-border)",
              overflowX: "auto",
            }}
          >
            <table className="w-full text-left" style={{ minWidth: 480 }}>
              <tbody>
                {grouped[cat].map((kw, idx) => (
                  <tr
                    key={kw.id}
                    style={{
                      borderTop: idx === 0 ? "none" : "1px solid var(--color-border-subtle)",
                      backgroundColor:
                        idx % 2 === 0 ? "var(--color-surface-1)" : "var(--color-surface-0)",
                      transition: "background-color 120ms ease",
                    }}
                    onMouseOver={(e) => {
                      (e.currentTarget as HTMLTableRowElement).style.backgroundColor =
                        "var(--color-surface-2)";
                    }}
                    onMouseOut={(e) => {
                      (e.currentTarget as HTMLTableRowElement).style.backgroundColor =
                        idx % 2 === 0 ? "var(--color-surface-1)" : "var(--color-surface-0)";
                    }}
                  >
                    {/* Term + incident badges */}
                    <td
                      className="px-4 py-2.5 text-sm"
                      style={{ color: "var(--color-text-primary)" }}
                    >
                      <span className="inline-flex items-center gap-2 flex-wrap">
                        <span>{kw.term}</span>
                        {getLinkedIncidents(kw.id).map((incName) => (
                          <span
                            key={incName}
                            style={{
                              display: "inline-block",
                              padding: "1px 7px",
                              borderRadius: 4,
                              fontSize: 10,
                              fontWeight: 500,
                              background: "rgba(251, 191, 36, 0.10)",
                              color: "var(--color-warning)",
                              border: "1px solid rgba(251, 191, 36, 0.30)",
                            }}
                          >
                            {incName}
                          </span>
                        ))}
                      </span>
                    </td>

                    {/* Enabled toggle */}
                    <td className="px-4 py-2.5 text-right">
                      {isAdmin ? (
                        <button
                          onClick={() => handleToggleEnabled(kw)}
                          style={{
                            position: "relative",
                            display: "inline-flex",
                            height: 20,
                            width: 36,
                            alignItems: "center",
                            borderRadius: 10,
                            border: "none",
                            cursor: "pointer",
                            transition: "background 200ms ease",
                            background: kw.enabled
                              ? "var(--color-accent)"
                              : "var(--color-surface-4)",
                          }}
                          title={kw.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
                        >
                          <span
                            style={{
                              position: "absolute",
                              width: 14,
                              height: 14,
                              borderRadius: "50%",
                              background: "white",
                              boxShadow: "0 1px 3px rgba(0,0,0,0.4)",
                              transition: "transform 200ms ease",
                              transform: kw.enabled ? "translateX(19px)" : "translateX(3px)",
                            }}
                          />
                        </button>
                      ) : (
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: 4,
                            fontSize: 11,
                            fontWeight: 500,
                            background: kw.enabled
                              ? "var(--color-accent-muted)"
                              : "var(--color-surface-3)",
                            color: kw.enabled
                              ? "var(--color-accent)"
                              : "var(--color-text-tertiary)",
                          }}
                        >
                          {kw.enabled ? "On" : "Off"}
                        </span>
                      )}
                    </td>

                    {/* Admin actions */}
                    {isAdmin && (
                      <td className="px-4 py-2.5 text-right whitespace-nowrap">
                        <button
                          onClick={() => openEditForm(kw)}
                          style={{
                            fontSize: 12,
                            color: "var(--color-text-secondary)",
                            background: "none",
                            border: "none",
                            cursor: "pointer",
                            marginRight: 12,
                            transition: "color 120ms ease",
                          }}
                          onMouseOver={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "var(--color-text-primary)";
                          }}
                          onMouseOut={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.color =
                              "var(--color-text-secondary)";
                          }}
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(kw.id)}
                          style={{
                            fontSize: 12,
                            color: "var(--color-danger)",
                            background: "none",
                            border: "none",
                            cursor: "pointer",
                            opacity: 0.7,
                            transition: "opacity 120ms ease",
                          }}
                          onMouseOver={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.opacity = "1";
                          }}
                          onMouseOut={(e) => {
                            (e.currentTarget as HTMLButtonElement).style.opacity = "0.7";
                          }}
                        >
                          Delete
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}

      {/* Keyword form modal */}
      {showForm && (
        <KeywordForm
          keyword={editingKeyword}
          onSave={handleSave}
          onCancel={closeForm}
        />
      )}
    </div>
  );
}
