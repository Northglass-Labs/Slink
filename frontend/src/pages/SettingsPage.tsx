import { useState, type ReactNode } from "react";
import { useAuth } from "../hooks/useAuth";
import NotificationChannelsSection from "./settings/NotificationChannelsSection";
import TeamsWebhooksSection from "./settings/TeamsWebhooksSection";
import IncidentsSection from "./settings/IncidentsSection";
import SeverityRulesSection from "./settings/SeverityRulesSection";
import ApiSourcesSection from "./settings/ApiSourcesSection";
import QuickAddKeywordSection from "./settings/QuickAddKeywordSection";
import AuditLogSection from "./settings/AuditLogSection";
import DataRetentionSection from "./settings/DataRetentionSection";
import AboutSection from "./settings/AboutSection";

// Tab definition — id must be stable, label is what the user sees.
// Admin-gated tabs are filtered out when !isAdmin so viewers don't see
// empty panes they can't interact with.
type TabId =
  | "notifications"
  | "webhooks"
  | "incidents"
  | "severity"
  | "sources"
  | "keywords"
  | "retention"
  | "audit"
  | "about";

interface TabDef {
  id: TabId;
  label: string;
  adminOnly: boolean;
  render: (isAdmin: boolean) => ReactNode;
}

const TABS: TabDef[] = [
  {
    id: "notifications",
    label: "Notifications",
    adminOnly: false,
    render: (isAdmin) => <NotificationChannelsSection isAdmin={isAdmin} />,
  },
  { id: "webhooks", label: "Teams Webhooks", adminOnly: true, render: () => <TeamsWebhooksSection /> },
  { id: "incidents", label: "Incidents", adminOnly: true, render: () => <IncidentsSection /> },
  { id: "severity", label: "Severity Rules", adminOnly: true, render: () => <SeverityRulesSection /> },
  { id: "sources", label: "API Sources", adminOnly: false, render: () => <ApiSourcesSection /> },
  { id: "keywords", label: "Quick Add Keyword", adminOnly: true, render: () => <QuickAddKeywordSection /> },
  { id: "retention", label: "Data Retention", adminOnly: true, render: () => <DataRetentionSection /> },
  { id: "audit", label: "Audit Log", adminOnly: true, render: () => <AuditLogSection /> },
  { id: "about", label: "About", adminOnly: false, render: () => <AboutSection /> },
];

export default function SettingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const visibleTabs = TABS.filter((t) => isAdmin || !t.adminOnly);
  const [activeId, setActiveId] = useState<TabId>(visibleTabs[0]?.id ?? "notifications");
  const active = visibleTabs.find((t) => t.id === activeId) ?? visibleTabs[0];

  return (
    <div className="space-y-6">
      <h1
        className="text-xl font-semibold"
        style={{ color: "var(--color-text-primary)" }}
      >
        Settings
      </h1>

      <div className="flex flex-col md:flex-row gap-6">
        {/* Sidebar on desktop, horizontal scroll tabs on mobile */}
        <nav
          aria-label="Settings sections"
          className="md:w-48 md:flex-shrink-0 md:border-r md:pr-4"
          style={{ borderColor: "var(--color-border)" }}
        >
          <div className="flex md:flex-col gap-1 overflow-x-auto md:overflow-visible pb-2 md:pb-0">
            {visibleTabs.map((tab) => {
              const isActive = tab.id === activeId;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveId(tab.id)}
                  style={{
                    padding: "8px 12px",
                    borderRadius: 6,
                    fontSize: 13,
                    fontWeight: isActive ? 600 : 500,
                    fontFamily: "var(--font-sans)",
                    textAlign: "left",
                    whiteSpace: "nowrap",
                    border: "none",
                    cursor: "pointer",
                    background: isActive ? "var(--color-surface-2)" : "transparent",
                    color: isActive ? "var(--color-accent)" : "var(--color-text-secondary)",
                    transition: "background 120ms ease, color 120ms ease",
                  }}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Active section content */}
        <div className="flex-1 max-w-3xl min-w-0 space-y-6">
          {active?.render(isAdmin)}
        </div>
      </div>
    </div>
  );
}
