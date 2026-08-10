import { useMemo, useState } from "react";
import type { Keyword } from "../../types";
import api from "../../api";
import { Button, Input, Select } from "../../components/ui";

interface KeywordSelectorProps {
  keywords: Keyword[];
  selectedIds: number[];
  onToggle: (id: number) => void;
  onSelectAll: (ids: number[]) => void;
  onDeselectAll: (ids: number[]) => void;
  onKeywordCreated: (kw: Keyword) => void;
}

// Grouped keyword pill selector with inline filter and create row.
// Used by IncidentsSection for both add and edit forms.
export function KeywordSelector({
  keywords,
  selectedIds,
  onToggle,
  onSelectAll,
  onDeselectAll,
  onKeywordCreated,
}: KeywordSelectorProps) {
  const [filter, setFilter] = useState("");
  const [newTerm, setNewTerm] = useState("");
  const [newCategory, setNewCategory] = useState("brand");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Group keywords by category, applying the text filter
  const grouped = useMemo(() => {
    const filtered = keywords.filter((kw) =>
      kw.term.toLowerCase().includes(filter.toLowerCase())
    );
    return filtered.reduce<Record<string, Keyword[]>>((acc, kw) => {
      if (!acc[kw.category]) acc[kw.category] = [];
      acc[kw.category].push(kw);
      return acc;
    }, {});
  }, [keywords, filter]);

  const categoryOrder = ["brand", "threat_actor"];
  const sortedCategories = [
    ...categoryOrder.filter((c) => grouped[c]),
    ...Object.keys(grouped)
      .filter((c) => !categoryOrder.includes(c))
      .sort(),
  ];

  async function handleCreate() {
    if (!newTerm.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      const res = await api.post<Keyword>("/keywords", {
        term: newTerm.trim(),
        category: newCategory,
        enabled: true,
      });
      onKeywordCreated(res.data);
      setNewTerm("");
    } catch {
      setCreateError("Failed to create keyword.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div
      style={{
        border: "1px solid var(--color-border)",
        borderRadius: 8,
        padding: 12,
        background: "var(--color-surface-1)",
      }}
    >
      {/* Inline create row */}
      <div className="flex gap-2 items-center flex-wrap" style={{ marginBottom: 10 }}>
        <div style={{ flex: "1 1 140px" }}>
          <Input
            type="text"
            value={newTerm}
            onChange={(e) => setNewTerm(e.target.value)}
            placeholder="New keyword term..."
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleCreate();
              }
            }}
          />
        </div>
        <div style={{ minWidth: 120 }}>
          <Select
            value={newCategory}
            onChange={(e) => setNewCategory(e.target.value)}
          >
            <option value="brand">brand</option>
            <option value="threat_actor">threat_actor</option>
            <option value="custom">custom</option>
          </Select>
        </div>
        <Button
          type="button"
          size="sm"
          onClick={handleCreate}
          disabled={creating || !newTerm.trim()}
        >
          {creating ? "..." : "+ Add"}
        </Button>
      </div>
      {createError && (
        <p style={{ fontSize: 11, color: "var(--color-danger)", marginBottom: 8 }}>
          {createError}
        </p>
      )}

      {/* Filter input */}
      <div style={{ marginBottom: 10 }}>
        <Input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter keywords..."
        />
      </div>

      {/* Grouped keyword pills */}
      {sortedCategories.length === 0 && (
        <p style={{ fontSize: 12, color: "var(--color-text-tertiary)" }}>
          {filter ? "No keywords match filter." : "No keywords available."}
        </p>
      )}
      {sortedCategories.map((cat) => {
        const catKeywords = grouped[cat];
        const catIds = catKeywords.map((kw) => kw.id);
        const allSelected = catIds.every((id) => selectedIds.includes(id));
        return (
          <div key={cat} style={{ marginBottom: 10 }}>
            {/* Category header */}
            <div className="flex items-center justify-between" style={{ marginBottom: 4 }}>
              <div className="flex items-center gap-2">
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.4px",
                    color: "var(--color-text-tertiary)",
                  }}
                >
                  {cat}
                </span>
                <span style={{ fontSize: 11, color: "var(--color-text-tertiary)" }}>
                  ({catKeywords.length})
                </span>
              </div>
              <button
                type="button"
                onClick={() => (allSelected ? onDeselectAll(catIds) : onSelectAll(catIds))}
                style={{
                  fontSize: 10,
                  color: "var(--color-text-tertiary)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  textDecoration: "underline",
                  padding: 0,
                }}
              >
                {allSelected ? "none" : "all"}
              </button>
            </div>
            {/* Pills */}
            <div className="flex flex-wrap gap-1">
              {catKeywords.map((kw) => {
                const selected = selectedIds.includes(kw.id);
                return (
                  <button
                    key={kw.id}
                    type="button"
                    onClick={() => onToggle(kw.id)}
                    style={{
                      display: "inline-block",
                      padding: "3px 10px",
                      borderRadius: 20,
                      fontSize: 12,
                      cursor: "pointer",
                      background: selected
                        ? "var(--color-accent-muted)"
                        : "var(--color-surface-2)",
                      color: selected
                        ? "var(--color-accent)"
                        : "var(--color-text-secondary)",
                      border: selected
                        ? "1px solid var(--color-accent)"
                        : "1px solid var(--color-border)",
                      fontFamily: "var(--font-sans)",
                      transition: "all 120ms ease",
                    }}
                  >
                    {kw.term}
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
