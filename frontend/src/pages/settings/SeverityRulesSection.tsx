import { useEffect, useState } from "react";
import type { SeverityRule } from "../../types";
import api from "../../api";
import { Button, Input, SectionCard, Select } from "../../components/ui";

interface RuleFormData {
  source_pattern: string;
  keyword_category: string;
  base_severity: string;
  priority: number;
  enabled: boolean;
}

interface RuleFormProps {
  initial?: Partial<RuleFormData>;
  onSave: (data: RuleFormData) => Promise<void>;
  onCancel: () => void;
  submitLabel: string;
  submittingLabel: string;
}

// Single form component used for both create and edit modes.
function RuleForm({
  initial,
  onSave,
  onCancel,
  submitLabel,
  submittingLabel,
}: RuleFormProps) {
  const [form, setForm] = useState<RuleFormData>({
    source_pattern: initial?.source_pattern ?? "",
    keyword_category: initial?.keyword_category ?? "",
    base_severity: initial?.base_severity ?? "medium",
    priority: initial?.priority ?? 50,
    enabled: initial?.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSave(form);
    } catch {
      setError("Failed to save rule.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <div
        style={{
          background: "var(--color-surface-0)",
          border: "1px solid var(--color-border)",
          borderRadius: 8,
          padding: 16,
          marginBottom: 8,
        }}
      >
        <div className="flex gap-3 flex-wrap" style={{ marginBottom: 12 }}>
          <div style={{ width: 90 }}>
            <Input
              label="Priority"
              type="number"
              value={form.priority}
              onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })}
            />
          </div>
          <div style={{ flex: "1 1 140px" }}>
            <Input
              label="Source Pattern"
              type="text"
              value={form.source_pattern}
              onChange={(e) => setForm({ ...form, source_pattern: e.target.value })}
              placeholder="e.g. ransomwatch (blank = any)"
            />
          </div>
          <div style={{ flex: "1 1 140px" }}>
            <Input
              label="Keyword Category"
              type="text"
              value={form.keyword_category}
              onChange={(e) => setForm({ ...form, keyword_category: e.target.value })}
              placeholder="e.g. brand (blank = any)"
            />
          </div>
          <div>
            <Select
              label="Severity"
              value={form.base_severity}
              onChange={(e) => setForm({ ...form, base_severity: e.target.value })}
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Select>
          </div>
          <div style={{ display: "flex", alignItems: "flex-end", paddingBottom: 2 }}>
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
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                style={{ accentColor: "var(--color-accent)" }}
              />
              Enabled
            </label>
          </div>
        </div>
        <div className="flex gap-2">
          <Button type="submit" disabled={saving}>
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
    </form>
  );
}

export default function SeverityRulesSection() {
  const [rules, setRules] = useState<SeverityRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  async function loadRules() {
    setLoading(true);
    try {
      const r = await api.get<SeverityRule[]>("/severity-rules");
      setRules(r.data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadRules();
  }, []);

  // Convert form data to the API request shape (blank → null).
  function toRequest(data: RuleFormData) {
    return {
      source_pattern: data.source_pattern.trim() || null,
      keyword_category: data.keyword_category.trim() || null,
      base_severity: data.base_severity,
      priority: data.priority,
      enabled: data.enabled,
    };
  }

  async function handleCreate(data: RuleFormData) {
    await api.post("/severity-rules", toRequest(data));
    setShowNew(false);
    await loadRules();
  }

  async function handleUpdate(id: number, data: RuleFormData) {
    await api.put(`/severity-rules/${id}`, toRequest(data));
    setEditingId(null);
    await loadRules();
  }

  async function handleToggleRule(rule: SeverityRule) {
    try {
      await api.put(`/severity-rules/${rule.id}`, {
        source_pattern: rule.source_pattern,
        keyword_category: rule.keyword_category,
        base_severity: rule.base_severity,
        priority: rule.priority,
        enabled: !rule.enabled,
      });
      await loadRules();
    } catch {
      // ignore
    }
  }

  async function handleDeleteRule(id: number) {
    if (!confirm("Delete this severity rule?")) return;
    setDeletingId(id);
    try {
      await api.delete(`/severity-rules/${id}`);
      setRules((prev) => prev.filter((r) => r.id !== id));
    } catch {
      // ignore
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <SectionCard title="Severity Rules">
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 16 }}>
        Control how detection severity is assigned based on source and keyword category.
        Higher priority rules are evaluated first.
      </p>

      {loading ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>Loading...</p>
      ) : (
        <>
          {rules.length === 0 && !showNew ? (
            <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 12 }}>
              No severity rules configured.
            </p>
          ) : (
            <div style={{ marginBottom: 16, overflowX: "auto" }}>
              {/* Table header */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "60px 1fr 1fr auto 70px auto",
                  gap: 8,
                  padding: "6px 0",
                  borderBottom: "1px solid var(--color-border)",
                  fontSize: 11,
                  fontWeight: 600,
                  color: "var(--color-text-tertiary)",
                  textTransform: "uppercase",
                  letterSpacing: "0.4px",
                  minWidth: 600,
                }}
              >
                <span>Priority</span>
                <span>Source Pattern</span>
                <span>Category</span>
                <span>Severity</span>
                <span>Enabled</span>
                <span>Actions</span>
              </div>

              {[...rules]
                .sort((a, b) => b.priority - a.priority)
                .map((rule) =>
                  editingId === rule.id ? (
                    <div
                      key={rule.id}
                      style={{
                        padding: "12px 0",
                        borderBottom: "1px solid var(--color-border-subtle)",
                      }}
                    >
                      <RuleForm
                        initial={{
                          source_pattern: rule.source_pattern || "",
                          keyword_category: rule.keyword_category || "",
                          base_severity: rule.base_severity,
                          priority: rule.priority,
                          enabled: rule.enabled,
                        }}
                        onSave={(data) => handleUpdate(rule.id, data)}
                        onCancel={() => setEditingId(null)}
                        submitLabel="Save"
                        submittingLabel="Saving..."
                      />
                    </div>
                  ) : (
                    <div
                      key={rule.id}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "60px 1fr 1fr auto 70px auto",
                        gap: 8,
                        alignItems: "center",
                        padding: "10px 0",
                        borderBottom: "1px solid var(--color-border-subtle)",
                        opacity: rule.enabled ? 1 : 0.5,
                        minWidth: 600,
                      }}
                    >
                      <span style={{ fontSize: 13, fontWeight: 600, color: "var(--color-text-primary)" }}>
                        {rule.priority}
                      </span>
                      <span
                        style={{
                          fontSize: 13,
                          color: "var(--color-text-secondary)",
                          fontFamily: "var(--font-mono, monospace)",
                        }}
                      >
                        {rule.source_pattern || "*"}
                      </span>
                      <span style={{ fontSize: 13, color: "var(--color-text-secondary)" }}>
                        {rule.keyword_category || "*"}
                      </span>
                      <span
                        style={{
                          fontSize: 11,
                          fontWeight: 600,
                          padding: "2px 8px",
                          borderRadius: 4,
                          textTransform: "uppercase",
                          background:
                            rule.base_severity === "critical"
                              ? "rgba(239,68,68,0.12)"
                              : rule.base_severity === "high"
                              ? "rgba(249,115,22,0.12)"
                              : rule.base_severity === "medium"
                              ? "rgba(251,191,36,0.12)"
                              : "rgba(96,165,250,0.12)",
                          color:
                            rule.base_severity === "critical"
                              ? "var(--color-danger)"
                              : rule.base_severity === "high"
                              ? "#f97316"
                              : rule.base_severity === "medium"
                              ? "#f59e0b"
                              : "var(--color-info)",
                        }}
                      >
                        {rule.base_severity}
                      </span>
                      <button
                        onClick={() => handleToggleRule(rule)}
                        style={{
                          padding: "3px 10px",
                          borderRadius: 4,
                          fontSize: 11,
                          fontWeight: 500,
                          fontFamily: "var(--font-sans)",
                          border: "none",
                          cursor: "pointer",
                          background: rule.enabled ? "rgba(52,211,153,0.12)" : "rgba(239,68,68,0.10)",
                          color: rule.enabled ? "var(--color-success)" : "var(--color-danger)",
                        }}
                      >
                        {rule.enabled ? "On" : "Off"}
                      </button>
                      <div className="flex gap-1">
                        <Button size="sm" variant="secondary" onClick={() => setEditingId(rule.id)}>
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => handleDeleteRule(rule.id)}
                          disabled={deletingId === rule.id}
                        >
                          Del
                        </Button>
                      </div>
                    </div>
                  )
                )}
            </div>
          )}

          {showNew ? (
            <RuleForm
              onSave={handleCreate}
              onCancel={() => setShowNew(false)}
              submitLabel="Add Rule"
              submittingLabel="Creating..."
            />
          ) : (
            <Button onClick={() => setShowNew(true)}>+ Add Rule</Button>
          )}
        </>
      )}
    </SectionCard>
  );
}
