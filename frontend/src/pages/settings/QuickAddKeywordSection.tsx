import { useState } from "react";
import type { Keyword } from "../../types";
import api from "../../api";
import { Button, Input, SectionCard, Select } from "../../components/ui";

export default function QuickAddKeywordSection() {
  const [term, setTerm] = useState("");
  const [category, setCategory] = useState("brand");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!term.trim()) return;

    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      await api.post<Keyword>("/keywords", {
        term: term.trim(),
        category,
        enabled: true,
      });
      setSuccess(`"${term.trim()}" added to watchlist.`);
      setTerm("");
    } catch {
      setError("Failed to add keyword. Check permissions.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SectionCard title="Quick Add Brand Keyword">
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", marginBottom: 16 }}>
        Add a brand keyword to the active watchlist without visiting the full
        Watchlist page.
      </p>
      <form onSubmit={handleSubmit}>
        <div className="flex gap-3 flex-wrap items-end">
          <div style={{ flex: "1 1 200px" }}>
            <Input
              label="Keyword term"
              type="text"
              value={term}
              onChange={(e) => setTerm(e.target.value)}
              placeholder="e.g. ACME Corp"
              required
            />
          </div>
          <div>
            <Select
              label="Category"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              <option value="brand">Brand</option>
              <option value="threat_actor">Threat Actor</option>
            </Select>
          </div>
          <Button type="submit" disabled={saving || !term.trim()}>
            {saving ? "Adding…" : "Add Keyword"}
          </Button>
        </div>

        {success && (
          <p
            className="animate-fade-in"
            style={{ marginTop: 10, fontSize: 13, color: "var(--color-success)" }}
          >
            {success}
          </p>
        )}
        {error && (
          <p
            className="animate-fade-in"
            style={{ marginTop: 10, fontSize: 13, color: "var(--color-danger)" }}
          >
            {error}
          </p>
        )}
      </form>
    </SectionCard>
  );
}
