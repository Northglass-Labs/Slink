import { useEffect, useState } from "react";
import type { Webhook } from "../../types";
import api from "../../api";
import { Button, Input, SectionCard, Select } from "../../components/ui";

interface WebhookFormData {
  name: string;
  url: string;
  severity_filter: string;
  enabled: boolean;
}

interface WebhookFormProps {
  initial?: Partial<WebhookFormData>;
  onSave: (data: WebhookFormData) => Promise<void>;
  onCancel: () => void;
  submitLabel: string;
  submittingLabel: string;
}

// Single form component used for both create and edit. Switching between
// modes is just a matter of passing or omitting `initial`.
function WebhookForm({
  initial,
  onSave,
  onCancel,
  submitLabel,
  submittingLabel,
}: WebhookFormProps) {
  const [form, setForm] = useState<WebhookFormData>({
    name: initial?.name ?? "",
    url: initial?.url ?? "",
    severity_filter: initial?.severity_filter ?? "all",
    enabled: initial?.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name.trim() || !form.url.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onSave({
        ...form,
        name: form.name.trim(),
        url: form.url.trim(),
      });
    } catch {
      setError("Failed to save webhook. Check the URL and permissions.");
    } finally {
      setSaving(false);
    }
  }

  const disabled = saving || !form.name.trim() || !form.url.trim();

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
          <div style={{ flex: "1 1 160px" }}>
            <Input
              label="Name"
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. SOC Chat"
              required
            />
          </div>
          <div style={{ flex: "3 1 320px" }}>
            <Input
              label="Webhook URL"
              type="url"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              placeholder="https://prod-…/workflows/…"
              required
            />
          </div>
          <div>
            <Select
              label="Severity Filter"
              value={form.severity_filter}
              onChange={(e) => setForm({ ...form, severity_filter: e.target.value })}
            >
              <option value="all">All severities</option>
              <option value="critical,high">Critical + High</option>
              <option value="critical">Critical only</option>
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
          <Button type="submit" disabled={disabled}>
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

export default function TeamsWebhooksSection() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [testResults, setTestResults] = useState<
    Record<number, { ok: boolean; message: string }>
  >({});
  const [testingId, setTestingId] = useState<number | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  async function loadWebhooks() {
    setLoading(true);
    try {
      const r = await api.get<Webhook[]>("/webhooks");
      setWebhooks(r.data);
    } catch {
      // silently fail — only admins see this section
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadWebhooks();
  }, []);

  async function handleCreate(data: WebhookFormData) {
    await api.post<Webhook>("/webhooks", data);
    setShowAdd(false);
    await loadWebhooks();
  }

  async function handleUpdate(id: number, data: WebhookFormData) {
    await api.put(`/webhooks/${id}`, data);
    setEditingId(null);
    await loadWebhooks();
  }

  async function handleToggleWebhook(wh: Webhook) {
    try {
      const updated = await api.put<Webhook>(`/webhooks/${wh.id}`, {
        enabled: !wh.enabled,
      });
      setWebhooks((prev) => prev.map((w) => (w.id === wh.id ? updated.data : w)));
    } catch {
      // ignore
    }
  }

  async function handleDeleteWebhook(id: number) {
    setDeletingId(id);
    try {
      await api.delete(`/webhooks/${id}`);
      setWebhooks((prev) => prev.filter((w) => w.id !== id));
    } catch {
      // ignore
    } finally {
      setDeletingId(null);
    }
  }

  async function handleTestWebhook(id: number) {
    setTestingId(id);
    setTestResults((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
    try {
      const r = await api.post<{ success: boolean; message: string }>(
        `/webhooks/${id}/test`
      );
      setTestResults((prev) => ({
        ...prev,
        [id]: { ok: r.data.success, message: r.data.message },
      }));
    } catch {
      setTestResults((prev) => ({
        ...prev,
        [id]: { ok: false, message: "Request failed — check network." },
      }));
    } finally {
      setTestingId(null);
    }
  }

  return (
    <SectionCard title="Teams Webhooks">
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 16 }}>
        Manage additional Teams webhook destinations. Each webhook can filter by
        severity so you can route critical-only alerts to the CISO chat and
        all-severity alerts to the SOC channel.
      </p>

      {loading ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>Loading…</p>
      ) : webhooks.length === 0 ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 12 }}>
          No webhooks configured yet.
        </p>
      ) : (
        <div style={{ marginBottom: 16 }}>
          {/* Table header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 2fr auto auto auto auto auto",
              gap: 8,
              padding: "6px 0",
              borderBottom: "1px solid var(--color-border)",
              fontSize: 11,
              fontWeight: 600,
              color: "var(--color-text-tertiary)",
              textTransform: "uppercase",
              letterSpacing: "0.4px",
            }}
          >
            <span>Name</span>
            <span>URL</span>
            <span>Filter</span>
            <span>Status</span>
            <span></span>
            <span></span>
            <span></span>
          </div>

          {webhooks.map((wh) =>
            editingId === wh.id ? (
              <div
                key={wh.id}
                style={{
                  padding: "12px 0",
                  borderBottom: "1px solid var(--color-border-subtle)",
                }}
              >
                <WebhookForm
                  initial={wh}
                  onSave={(data) => handleUpdate(wh.id, data)}
                  onCancel={() => setEditingId(null)}
                  submitLabel="Save Changes"
                  submittingLabel="Saving…"
                />
              </div>
            ) : (
              <div
                key={wh.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 2fr auto auto auto auto auto",
                  gap: 8,
                  alignItems: "center",
                  padding: "10px 0",
                  borderBottom: "1px solid var(--color-border-subtle)",
                }}
              >
                <span style={{ fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)" }}>
                  {wh.name}
                </span>
                <span
                  style={{
                    fontSize: 11,
                    color: "var(--color-text-tertiary)",
                    fontFamily: "var(--font-mono, monospace)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={wh.url}
                >
                  {wh.url.length > 60 ? wh.url.slice(0, 60) + "…" : wh.url}
                </span>
                <span
                  style={{
                    fontSize: 11,
                    padding: "2px 8px",
                    borderRadius: 4,
                    background: "var(--color-surface-2)",
                    color: "var(--color-text-secondary)",
                    whiteSpace: "nowrap",
                  }}
                >
                  {wh.severity_filter}
                </span>
                <button
                  onClick={() => handleToggleWebhook(wh)}
                  style={{
                    padding: "3px 10px",
                    borderRadius: 4,
                    fontSize: 11,
                    fontWeight: 500,
                    fontFamily: "var(--font-sans)",
                    border: "none",
                    cursor: "pointer",
                    background: wh.enabled ? "rgba(52,211,153,0.12)" : "rgba(239,68,68,0.10)",
                    color: wh.enabled ? "var(--color-success)" : "var(--color-danger)",
                  }}
                  title={wh.enabled ? "Click to disable" : "Click to enable"}
                >
                  {wh.enabled ? "Enabled" : "Disabled"}
                </button>
                <div>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleTestWebhook(wh.id)}
                    disabled={testingId === wh.id}
                  >
                    {testingId === wh.id ? "Testing…" : "Test"}
                  </Button>
                  {testResults[wh.id] && (
                    <div
                      style={{
                        marginTop: 4,
                        fontSize: 11,
                        color: testResults[wh.id].ok
                          ? "var(--color-success)"
                          : "var(--color-danger)",
                      }}
                    >
                      {testResults[wh.id].ok ? "✓ " : "✗ "}
                      {testResults[wh.id].message.length > 60
                        ? testResults[wh.id].message.slice(0, 60) + "…"
                        : testResults[wh.id].message}
                    </div>
                  )}
                </div>
                <Button size="sm" variant="secondary" onClick={() => setEditingId(wh.id)}>
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  onClick={() => handleDeleteWebhook(wh.id)}
                  disabled={deletingId === wh.id}
                >
                  {deletingId === wh.id ? "…" : "Delete"}
                </Button>
              </div>
            )
          )}
        </div>
      )}

      {showAdd ? (
        <WebhookForm
          onSave={handleCreate}
          onCancel={() => setShowAdd(false)}
          submitLabel="Save Webhook"
          submittingLabel="Saving…"
        />
      ) : (
        <Button onClick={() => setShowAdd(true)}>+ Add Webhook</Button>
      )}
    </SectionCard>
  );
}
