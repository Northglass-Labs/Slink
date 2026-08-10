import { useState, useEffect } from "react";
import type { UserInfo } from "../types";
import api from "../api";
import { useAuth } from "../hooks/useAuth";
import { Navigate } from "react-router-dom";

export default function UserManagement() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [users, setUsers] = useState<UserInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  // Create form state
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");
  const [formError, setFormError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function fetchUsers() {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<UserInfo[]>("/auth/users");
      setUsers(res.data);
    } catch {
      setError("Failed to load users.");
    } finally {
      setLoading(false);
    }
  }

  // Rules of Hooks: all hooks must run on every render. The admin gate is
  // applied via early return BELOW the hooks block, not above it.
  useEffect(() => {
    if (!isAdmin) return;
    fetchUsers();
  }, [isAdmin]);

  // Non-admins shouldn't see this page
  if (!isAdmin) {
    return <Navigate to="/dashboard" replace />;
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);

    if (newPassword.length < 12) {
      setFormError("Password must be at least 12 characters.");
      return;
    }

    setCreating(true);
    try {
      const res = await api.post<UserInfo>("/auth/users", {
        username: newUsername,
        password: newPassword,
        role: newRole,
      });
      setUsers((prev) => [...prev, res.data]);
      setShowForm(false);
      setNewUsername("");
      setNewPassword("");
      setNewRole("viewer");
    } catch (err: unknown) {
      if (
        err &&
        typeof err === "object" &&
        "response" in err &&
        (err as { response?: { status?: number } }).response?.status === 409
      ) {
        setFormError("Username already exists.");
      } else if (
        err &&
        typeof err === "object" &&
        "response" in err &&
        (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
      ) {
        setFormError(
          (err as { response: { data: { detail: string } } }).response.data.detail
        );
      } else {
        setFormError("Failed to create user.");
      }
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(targetUser: UserInfo) {
    if (!confirm(`Are you sure you want to delete user ${targetUser.username}?`)) return;
    try {
      await api.delete(`/auth/users/${targetUser.id}`);
      setUsers((prev) => prev.filter((u) => u.id !== targetUser.id));
    } catch {
      setError("Failed to delete user.");
    }
  }

  function formatDate(dateStr: string | null): string {
    if (!dateStr) return "—";
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1
            className="text-xl font-semibold"
            style={{ color: "var(--color-text-primary)" }}
          >
            User Management
          </h1>
          <span
            style={{
              fontSize: 12,
              color: "var(--color-text-tertiary)",
              fontWeight: 500,
            }}
          >
            {users.length} user{users.length !== 1 ? "s" : ""}
          </span>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
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
          + Create User
        </button>
      </div>

      {/* Error banner */}
      {error && (
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
          {error}
        </div>
      )}

      {/* Create user form (inline) */}
      {showForm && (
        <div
          style={{
            padding: "20px",
            borderRadius: 8,
            border: "1px solid var(--color-border)",
            backgroundColor: "var(--color-surface-1)",
          }}
        >
          <h2
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: "var(--color-text-primary)",
              marginBottom: 16,
            }}
          >
            Create New User
          </h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div className="flex gap-4 flex-wrap">
              {/* Username */}
              <div className="flex flex-col gap-1">
                <label
                  style={{ fontSize: 12, color: "var(--color-text-secondary)" }}
                >
                  Username
                </label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  required
                  style={{
                    padding: "7px 12px",
                    borderRadius: 6,
                    border: "1px solid var(--color-border)",
                    backgroundColor: "var(--color-surface-0)",
                    color: "var(--color-text-primary)",
                    fontSize: 13,
                    width: 200,
                  }}
                  placeholder="username"
                />
              </div>

              {/* Password */}
              <div className="flex flex-col gap-1">
                <label
                  style={{ fontSize: 12, color: "var(--color-text-secondary)" }}
                >
                  Password (min 12 chars)
                </label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  minLength={12}
                  style={{
                    padding: "7px 12px",
                    borderRadius: 6,
                    border: "1px solid var(--color-border)",
                    backgroundColor: "var(--color-surface-0)",
                    color: "var(--color-text-primary)",
                    fontSize: 13,
                    width: 220,
                  }}
                  placeholder="min 12 characters"
                />
              </div>

              {/* Role */}
              <div className="flex flex-col gap-1">
                <label
                  style={{ fontSize: 12, color: "var(--color-text-secondary)" }}
                >
                  Role
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  style={{
                    padding: "7px 12px",
                    borderRadius: 6,
                    border: "1px solid var(--color-border)",
                    backgroundColor: "var(--color-surface-0)",
                    color: "var(--color-text-primary)",
                    fontSize: 13,
                    width: 130,
                  }}
                >
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            </div>

            {/* Form error */}
            {formError && (
              <div
                style={{
                  fontSize: 12,
                  color: "var(--color-danger)",
                  padding: "6px 0",
                }}
              >
                {formError}
              </div>
            )}

            {/* Form actions */}
            <div className="flex gap-3">
              <button
                type="submit"
                disabled={creating}
                style={{
                  padding: "7px 16px",
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 500,
                  background: "var(--color-accent)",
                  color: "var(--color-text-inverse)",
                  border: "none",
                  cursor: creating ? "not-allowed" : "pointer",
                  opacity: creating ? 0.6 : 1,
                  transition: "opacity 120ms ease",
                }}
              >
                {creating ? "Creating…" : "Create User"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowForm(false);
                  setFormError(null);
                }}
                style={{
                  padding: "7px 16px",
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 500,
                  background: "var(--color-surface-3)",
                  color: "var(--color-text-secondary)",
                  border: "none",
                  cursor: "pointer",
                  transition: "opacity 120ms ease",
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>
          Loading users…
        </p>
      )}

      {/* Empty state */}
      {!loading && users.length === 0 && !error && (
        <p style={{ color: "var(--color-text-tertiary)", fontSize: 13 }}>
          No users found.
        </p>
      )}

      {/* Users table */}
      {!loading && users.length > 0 && (
        <div
          style={{
            borderRadius: 8,
            border: "1px solid var(--color-border)",
            overflowX: "auto",
          }}
        >
          <table className="w-full text-left" style={{ minWidth: 600 }}>
            <thead>
              <tr
                style={{
                  backgroundColor: "var(--color-surface-2)",
                  borderBottom: "1px solid var(--color-border)",
                }}
              >
                <th
                  className="px-4 py-2.5"
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.7px",
                    color: "var(--color-text-tertiary)",
                  }}
                >
                  Username
                </th>
                <th
                  className="px-4 py-2.5"
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.7px",
                    color: "var(--color-text-tertiary)",
                  }}
                >
                  Role
                </th>
                <th
                  className="px-4 py-2.5"
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.7px",
                    color: "var(--color-text-tertiary)",
                  }}
                >
                  Created
                </th>
                <th
                  className="px-4 py-2.5 text-right"
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.7px",
                    color: "var(--color-text-tertiary)",
                  }}
                >
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u, idx) => (
                <tr
                  key={u.id}
                  style={{
                    borderTop:
                      idx === 0 ? "none" : "1px solid var(--color-border-subtle)",
                    backgroundColor:
                      idx % 2 === 0
                        ? "var(--color-surface-1)"
                        : "var(--color-surface-0)",
                    transition: "background-color 120ms ease",
                  }}
                  onMouseOver={(e) => {
                    (
                      e.currentTarget as HTMLTableRowElement
                    ).style.backgroundColor = "var(--color-surface-2)";
                  }}
                  onMouseOut={(e) => {
                    (
                      e.currentTarget as HTMLTableRowElement
                    ).style.backgroundColor =
                      idx % 2 === 0
                        ? "var(--color-surface-1)"
                        : "var(--color-surface-0)";
                  }}
                >
                  {/* Username */}
                  <td
                    className="px-4 py-2.5 text-sm"
                    style={{ color: "var(--color-text-primary)" }}
                  >
                    {u.username}
                  </td>

                  {/* Role badge */}
                  <td className="px-4 py-2.5">
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 8px",
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 500,
                        textTransform: "uppercase",
                        letterSpacing: "0.5px",
                        background:
                          u.role === "admin"
                            ? "var(--color-accent-muted)"
                            : "var(--color-surface-3)",
                        color:
                          u.role === "admin"
                            ? "var(--color-accent)"
                            : "var(--color-text-tertiary)",
                      }}
                    >
                      {u.role}
                    </span>
                  </td>

                  {/* Created date */}
                  <td
                    className="px-4 py-2.5 text-sm"
                    style={{ color: "var(--color-text-secondary)" }}
                  >
                    {formatDate(u.created_at)}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-2.5 text-right">
                    <button
                      onClick={() => handleDelete(u)}
                      disabled={u.username === user?.username}
                      style={{
                        fontSize: 12,
                        color:
                          u.username === user?.username
                            ? "var(--color-text-tertiary)"
                            : "var(--color-danger)",
                        background: "none",
                        border: "none",
                        cursor:
                          u.username === user?.username
                            ? "not-allowed"
                            : "pointer",
                        opacity: u.username === user?.username ? 0.4 : 0.7,
                        transition: "opacity 120ms ease",
                      }}
                      onMouseOver={(e) => {
                        if (u.username !== user?.username) {
                          (e.currentTarget as HTMLButtonElement).style.opacity =
                            "1";
                        }
                      }}
                      onMouseOut={(e) => {
                        (e.currentTarget as HTMLButtonElement).style.opacity =
                          u.username === user?.username ? "0.4" : "0.7";
                      }}
                      title={
                        u.username === user?.username
                          ? "Cannot delete yourself"
                          : `Delete ${u.username}`
                      }
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
