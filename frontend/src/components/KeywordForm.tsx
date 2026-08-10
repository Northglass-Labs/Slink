import { useState } from "react";
import type { Keyword } from "../types";
import api from "../api";

interface Props {
  keyword?: Keyword; // if provided, we're editing; otherwise creating
  onSave: (keyword: Keyword) => void;
  onCancel: () => void;
}

const PRESET_CATEGORIES = ["brand", "threat_actor"];

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "9px 12px",
  borderRadius: 8,
  fontSize: 13,
  fontFamily: "var(--font-sans)",
  background: "var(--color-surface-0)",
  border: "1px solid var(--color-border)",
  color: "var(--color-text-primary)",
  outline: "none",
  transition: "border-color 150ms ease, box-shadow 150ms ease",
};

function InputField(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      style={inputStyle}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = "var(--color-accent)";
        e.currentTarget.style.boxShadow = "0 0 0 3px var(--color-accent-muted)";
        props.onFocus?.(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = "var(--color-border)";
        e.currentTarget.style.boxShadow = "none";
        props.onBlur?.(e);
      }}
    />
  );
}

function SelectField(props: React.SelectHTMLAttributes<HTMLSelectElement> & { children: React.ReactNode }) {
  return (
    <select
      {...props}
      style={inputStyle}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = "var(--color-accent)";
        e.currentTarget.style.boxShadow = "0 0 0 3px var(--color-accent-muted)";
        props.onFocus?.(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = "var(--color-border)";
        e.currentTarget.style.boxShadow = "none";
        props.onBlur?.(e);
      }}
    >
      {props.children}
    </select>
  );
}

export default function KeywordForm({ keyword, onSave, onCancel }: Props) {
  const [term, setTerm] = useState(keyword?.term ?? "");
  const [category, setCategory] = useState(keyword?.category ?? "brand");
  const [customCategory, setCustomCategory] = useState(
    keyword && !PRESET_CATEGORIES.includes(keyword.category) ? keyword.category : ""
  );
  const [useCustom, setUseCustom] = useState(
    keyword ? !PRESET_CATEGORIES.includes(keyword.category) : false
  );
  const [enabled, setEnabled] = useState(keyword?.enabled ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const effectiveCategory = useCustom ? customCategory : category;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!term.trim() || !effectiveCategory.trim()) {
      setError("Term and category are required.");
      return;
    }

    setSaving(true);
    setError(null);
    try {
      let saved: Keyword;
      if (keyword) {
        const res = await api.put<Keyword>(`/keywords/${keyword.id}`, {
          term: term.trim(),
          category: effectiveCategory.trim(),
          enabled,
        });
        saved = res.data;
      } else {
        const res = await api.post<Keyword>("/keywords", {
          term: term.trim(),
          category: effectiveCategory.trim(),
          enabled,
        });
        saved = res.data;
      }
      onSave(saved);
    } catch {
      setError("Failed to save keyword.");
    } finally {
      setSaving(false);
    }
  }

  const labelStyle: React.CSSProperties = {
    display: "block",
    fontSize: 12,
    fontWeight: 500,
    color: "var(--color-text-secondary)",
    marginBottom: 6,
  };

  return (
    // Backdrop — clicking outside cancels
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 50,
      }}
      onClick={onCancel}
    >
      <div
        style={{
          background: "var(--color-surface-2)",
          border: "1px solid var(--color-border)",
          borderRadius: 12,
          padding: 24,
          width: "100%",
          maxWidth: 440,
          boxShadow: "0 8px 40px rgba(0,0,0,0.5)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2
          style={{
            fontSize: 16,
            fontWeight: 600,
            color: "var(--color-text-primary)",
            marginBottom: 20,
          }}
        >
          {keyword ? "Edit Keyword" : "Add Keyword"}
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Term */}
          <div>
            <label style={labelStyle}>Term</label>
            <InputField
              type="text"
              value={term}
              onChange={(e) => setTerm(e.target.value)}
              placeholder="e.g. ACME Corp"
              autoFocus
            />
          </div>

          {/* Category */}
          <div>
            <label style={labelStyle}>Category</label>
            <div className="flex gap-4 mb-2">
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: 13,
                  color: "var(--color-text-secondary)",
                  cursor: "pointer",
                }}
              >
                <input
                  type="radio"
                  checked={!useCustom}
                  onChange={() => setUseCustom(false)}
                  style={{ accentColor: "var(--color-accent)" }}
                />
                Preset
              </label>
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: 13,
                  color: "var(--color-text-secondary)",
                  cursor: "pointer",
                }}
              >
                <input
                  type="radio"
                  checked={useCustom}
                  onChange={() => setUseCustom(true)}
                  style={{ accentColor: "var(--color-accent)" }}
                />
                Custom (incident:*)
              </label>
            </div>

            {!useCustom ? (
              <SelectField
                value={category}
                onChange={(e) => setCategory(e.target.value)}
              >
                {PRESET_CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </SelectField>
            ) : (
              <InputField
                type="text"
                value={customCategory}
                onChange={(e) => setCustomCategory(e.target.value)}
                placeholder="e.g. incident:breach-2024"
              />
            )}
          </div>

          {/* Enabled */}
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              cursor: "pointer",
              fontSize: 13,
              color: "var(--color-text-secondary)",
            }}
          >
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              style={{ accentColor: "var(--color-accent)", width: 16, height: 16 }}
            />
            Enabled
          </label>

          {error && (
            <p style={{ fontSize: 13, color: "var(--color-danger)" }}>{error}</p>
          )}

          <div className="flex gap-3 pt-1">
            <button
              type="submit"
              disabled={saving}
              style={{
                flex: 1,
                padding: "9px 16px",
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 500,
                fontFamily: "var(--font-sans)",
                background: saving ? "var(--color-surface-4)" : "var(--color-accent)",
                color: saving ? "var(--color-text-secondary)" : "var(--color-text-inverse)",
                border: "none",
                cursor: saving ? "not-allowed" : "pointer",
                opacity: saving ? 0.7 : 1,
                boxShadow: saving ? "none" : "0 2px 8px var(--color-accent-glow)",
                transition: "all 150ms ease",
              }}
            >
              {saving ? "Saving…" : "Save"}
            </button>
            <button
              type="button"
              onClick={onCancel}
              style={{
                flex: 1,
                padding: "9px 16px",
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 500,
                fontFamily: "var(--font-sans)",
                background: "var(--color-surface-3)",
                border: "1px solid var(--color-border-bright)",
                color: "var(--color-text-primary)",
                cursor: "pointer",
                transition: "background 120ms ease",
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
