import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, screen } from "@testing-library/react";
import type { ReactElement } from "react";
import api from "../api";
import AuditLogSection from "./settings/AuditLogSection";
import NotificationChannelsSection from "./settings/NotificationChannelsSection";
import SeverityRulesSection from "./settings/SeverityRulesSection";
import TeamsWebhooksSection from "./settings/TeamsWebhooksSection";
import UserManagement from "./UserManagement";
import { deferred, renderStrict, settle, type Deferred } from "../test/helpers";

vi.mock("../api", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "admin-user", role: "admin" } }),
}));

const get = vi.mocked(api.get);

interface LoaderCase {
  name: string;
  url: string;
  loading: RegExp;
  element: () => ReactElement;
  payload: (label: string) => unknown;
}

const cases: LoaderCase[] = [
  {
    name: "AuditLogSection",
    url: "/audit",
    loading: /Loading audit log/,
    element: () => <AuditLogSection />,
    payload: (label) => ({
      items: [
        {
          id: 1,
          user_id: 1,
          username: label,
          action: "login",
          target_type: "user",
          target_id: null,
          detail: null,
          created_at: new Date().toISOString(),
        },
      ],
      total: 1,
    }),
  },
  {
    name: "NotificationChannelsSection",
    url: "/notification-channels",
    loading: /Loading\.\.\./,
    element: () => <NotificationChannelsSection isAdmin={true} />,
    payload: (label) => [{ channel_type: "pushover", enabled: true, display_name: label }],
  },
  {
    name: "SeverityRulesSection",
    url: "/severity-rules",
    loading: /Loading\.\.\./,
    element: () => <SeverityRulesSection />,
    payload: (label) => [
      {
        id: 1,
        source_pattern: label,
        keyword_category: null,
        base_severity: "high",
        priority: 1,
        enabled: true,
      },
    ],
  },
  {
    name: "TeamsWebhooksSection",
    url: "/webhooks",
    loading: /Loading…/,
    element: () => <TeamsWebhooksSection />,
    payload: (label) => [
      {
        id: 1,
        name: label,
        url: "https://example.invalid/hook",
        enabled: true,
        severity_filter: "all",
        created_at: "2026-11-01T00:00:00Z",
      },
    ],
  },
  {
    name: "UserManagement",
    url: "/auth/users",
    loading: /Loading users…/,
    element: () => <UserManagement />,
    payload: (label) => [{ id: 9, username: label, role: "viewer", created_at: null }],
  },
];

let pending: Deferred<{ data: unknown }>[];

beforeEach(() => {
  pending = [];
  get.mockReset();
  get.mockImplementation(() => {
    const d = deferred<{ data: unknown }>();
    pending.push(d);
    return d.promise;
  });
});

describe.each(cases)("$name loader", (c) => {
  it("shows loading, then the data", async () => {
    renderStrict(c.element());
    expect(screen.getByText(c.loading)).toBeTruthy();

    await act(async () => {
      for (const d of pending) d.resolve({ data: c.payload("alpha-row") });
    });
    expect(await screen.findByText("alpha-row")).toBeTruthy();
    expect(screen.queryByText(c.loading)).toBeNull();
  });

  it("ignores StrictMode's stale first response, even when it arrives last", async () => {
    renderStrict(c.element());
    expect(pending.length).toBeGreaterThanOrEqual(2); // StrictMode runs the effect twice

    const first = pending[0];
    const last = pending[pending.length - 1];
    await act(async () => last.resolve({ data: c.payload("fresh-row") }));
    expect(await screen.findByText("fresh-row")).toBeTruthy();

    await act(async () => first.resolve({ data: c.payload("stale-row") }));
    await settle();
    expect(screen.getByText("fresh-row")).toBeTruthy();
    expect(screen.queryByText("stale-row")).toBeNull();
  });

  it("logs no errors when the response arrives after unmount", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const { unmount } = renderStrict(c.element());
    unmount();
    await act(async () => {
      for (const d of pending) d.resolve({ data: c.payload("late-row") });
    });
    await settle();
    expect(errors).not.toHaveBeenCalled();
  });
});
