import { useEffect, useState } from "react";
import type { Note } from "../types";
import api from "../api";
import { timeAgo } from "../utils/time";

interface Props {
  detectionId: number;
  onCountChange?: (count: number) => void;
}

export default function NotesTab({ detectionId, onCountChange }: Props) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [content, setContent] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function fetchNotes() {
      setLoading(true);
      setError(null);
      try {
        const res = await api.get<Note[]>(`/detections/${detectionId}/notes`);
        if (!cancelled) {
          setNotes(res.data);
          onCountChange?.(res.data.length);
        }
      } catch {
        if (!cancelled) setError("Failed to load notes.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchNotes();
    return () => { cancelled = true; };
  }, [detectionId, onCountChange]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = content.trim();
    if (!trimmed) return;

    setSubmitting(true);
    setError(null);
    try {
      const res = await api.post<Note>(`/detections/${detectionId}/notes`, {
        content: trimmed,
      });
      const updated = [...notes, res.data];
      setNotes(updated);
      onCountChange?.(updated.length);
      setContent("");
    } catch {
      setError("Failed to add note.");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", padding: "12px 0" }}>
        Loading notes...
      </p>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {/* Notes list — oldest first */}
      {notes.length === 0 && !error && (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)", fontStyle: "italic" }}>
          No notes yet. Add the first one below.
        </p>
      )}

      {notes.map((note) => (
        <div
          key={note.id}
          style={{
            background: "var(--color-surface-0)",
            border: "1px solid var(--color-border)",
            borderRadius: 6,
            padding: "10px 14px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 6,
            }}
          >
            <span style={{ fontSize: 12, fontWeight: 600, color: "var(--color-accent)" }}>
              {note.username}
            </span>
            <span style={{ fontSize: 11, color: "var(--color-text-tertiary)" }}>
              {timeAgo(note.created_at)}
            </span>
          </div>
          <p
            style={{
              fontSize: 13,
              lineHeight: 1.5,
              color: "var(--color-text-primary)",
              margin: 0,
              whiteSpace: "pre-wrap",
            }}
          >
            {note.content}
          </p>
        </div>
      ))}

      {error && (
        <p style={{ fontSize: 13, color: "var(--color-danger)", margin: 0 }}>{error}</p>
      )}

      {/* New note form */}
      <form
        onSubmit={handleSubmit}
        style={{ display: "flex", gap: 8, alignItems: "flex-end" }}
        onClick={(e) => e.stopPropagation()}
      >
        <input
          type="text"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Add a note..."
          disabled={submitting}
          style={{
            flex: 1,
            padding: "8px 12px",
            fontSize: 13,
            fontFamily: "var(--font-sans)",
            background: "var(--color-surface-0)",
            border: "1px solid var(--color-border)",
            borderRadius: 6,
            color: "var(--color-text-primary)",
            outline: "none",
          }}
          onFocus={(e) => {
            e.currentTarget.style.borderColor = "var(--color-accent)";
          }}
          onBlur={(e) => {
            e.currentTarget.style.borderColor = "var(--color-border)";
          }}
        />
        <button
          type="submit"
          disabled={submitting || !content.trim()}
          style={{
            padding: "8px 16px",
            fontSize: 12,
            fontWeight: 600,
            fontFamily: "var(--font-sans)",
            background: "var(--color-accent-muted)",
            color: "var(--color-text-inverse)",
            border: "1px solid var(--color-accent)",
            borderRadius: 6,
            cursor: submitting || !content.trim() ? "not-allowed" : "pointer",
            opacity: submitting || !content.trim() ? 0.5 : 1,
            whiteSpace: "nowrap",
            transition: "opacity 120ms ease",
          }}
        >
          {submitting ? "Adding..." : "Add Note"}
        </button>
      </form>
    </div>
  );
}
