import { useEffect, useState } from "react";
import api from "../../api";
import { Button, SectionCard } from "../../components/ui";

export default function DataRetentionSection() {
  const [days, setDays] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Record<string, { value: string; description: string | null }>>("/settings")
      .then((r) => {
        if (r.data.retention_days) {
          setDays(r.data.retention_days.value);
        }
      })
      .catch(() => {
        // fail silently — retention field stays empty
      });
  }, []);

  async function handleSave() {
    const parsed = parseInt(days, 10);
    if (isNaN(parsed) || parsed < 1) {
      setError("Enter a positive number of days.");
      return;
    }
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await api.patch("/settings/retention_days", { value: String(parsed) });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      setError("Failed to save retention setting.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SectionCard title="Data Retention">
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 16 }}>
        Detections older than the retention period are exported as JSONL and
        pruned daily at 03:00 UTC.
      </p>
      <div className="flex items-center gap-3 flex-wrap">
        <label style={{ fontSize: 13, color: "var(--color-text-secondary)", fontWeight: 500 }}>
          Retention Period
        </label>
        <input
          type="number"
          min={1}
          value={days}
          onChange={(e) => {
            setDays(e.target.value);
            setSaved(false);
            setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              handleSave();
            }
          }}
          style={{
            width: 80,
            padding: "8px 12px",
            borderRadius: 8,
            fontSize: 13,
            fontFamily: "var(--font-sans)",
            background: "var(--color-surface-0)",
            border: "1px solid var(--color-border)",
            color: "var(--color-text-primary)",
            outline: "none",
            textAlign: "center",
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
        <span style={{ fontSize: 13, color: "var(--color-text-secondary)" }}>days</span>
        <Button onClick={handleSave} disabled={saving || !days}>
          {saving ? "Saving..." : "Save"}
        </Button>
        {saved && <span style={{ fontSize: 12, color: "var(--color-success)" }}>Saved</span>}
        {error && <span style={{ fontSize: 12, color: "var(--color-danger)" }}>{error}</span>}
      </div>
    </SectionCard>
  );
}
