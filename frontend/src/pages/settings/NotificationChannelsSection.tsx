import { useEffect, useState } from "react";
import api from "../../api";
import { Button, SectionCard } from "../../components/ui";
import { StatusIndicator } from "./StatusIndicator";

interface NotificationChannel {
  channel_type: string;
  enabled: boolean;
  display_name: string;
}

interface NotificationChannelsSectionProps {
  isAdmin: boolean;
}

const rowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "10px 0",
  borderBottom: "1px solid var(--color-border-subtle)",
};

export default function NotificationChannelsSection({ isAdmin }: NotificationChannelsSectionProps) {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [togglingChannel, setTogglingChannel] = useState<string | null>(null);
  const [testingChannel, setTestingChannel] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; message: string }>>({});

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    api
      .get<NotificationChannel[]>("/notification-channels")
      .then((r) => {
        if (mounted) setChannels(r.data);
      })
      .catch(() => {
        // fail silently — channels remain empty, toggles won't render
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  async function handleTestChannel(channelType: string) {
    setTestingChannel(channelType);
    // Clear any prior result for this channel before firing
    setTestResults((prev) => {
      const next = { ...prev };
      delete next[channelType];
      return next;
    });
    try {
      const r = await api.post<{ success: boolean; message: string }>(
        `/notification-channels/${channelType}/test`
      );
      setTestResults((prev) => ({
        ...prev,
        [channelType]: { ok: r.data.success, message: r.data.message },
      }));
    } catch (err: unknown) {
      const detail =
        err && typeof err === "object" && "response" in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : undefined;
      setTestResults((prev) => ({
        ...prev,
        [channelType]: { ok: false, message: detail || "Test failed" },
      }));
    } finally {
      setTestingChannel(null);
    }
  }

  async function handleToggleChannel(channelType: string, currentEnabled: boolean) {
    setTogglingChannel(channelType);
    try {
      const r = await api.patch<NotificationChannel>(
        `/notification-channels/${channelType}`,
        { enabled: !currentEnabled }
      );
      setChannels((prev) =>
        prev.map((c) => (c.channel_type === channelType ? r.data : c))
      );
    } catch {
      // ignore — UI stays as-is
    } finally {
      setTogglingChannel(null);
    }
  }

  return (
    <SectionCard title="Notification Channels">
      {loading ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>Loading...</p>
      ) : channels.length === 0 ? (
        <p style={{ fontSize: 13, color: "var(--color-text-tertiary)" }}>
          No notification channels configured.
        </p>
      ) : (
        <div>
          {channels.map((ch, idx) => (
            <div key={ch.channel_type}>
              <div
                style={{
                  ...rowStyle,
                  borderBottom:
                    idx === channels.length - 1 && !testResults[ch.channel_type]
                      ? "none"
                      : "1px solid var(--color-border-subtle)",
                }}
              >
                <div>
                  <span style={{ fontSize: 13, fontWeight: 500, color: "var(--color-text-primary)" }}>
                    {ch.display_name}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--color-text-tertiary)", marginLeft: 8 }}>
                    {ch.channel_type === "pushover" ? "Mobile push alerts" : "Adaptive Cards to Teams"}
                  </span>
                </div>
                {isAdmin ? (
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={testingChannel === ch.channel_type}
                      onClick={() => handleTestChannel(ch.channel_type)}
                    >
                      {testingChannel === ch.channel_type ? "Testing…" : "Test"}
                    </Button>
                    <Button
                      size="sm"
                      variant={ch.enabled ? "secondary" : "danger"}
                      disabled={togglingChannel === ch.channel_type}
                      onClick={() => handleToggleChannel(ch.channel_type, ch.enabled)}
                      title={ch.enabled ? "Click to disable" : "Click to enable"}
                    >
                      {ch.enabled ? "Enabled" : "Disabled"}
                    </Button>
                  </div>
                ) : (
                  <StatusIndicator ok={ch.enabled} okLabel="Enabled" failLabel="Disabled" />
                )}
              </div>
              {testResults[ch.channel_type] && (
                <div
                  style={{
                    paddingBottom: 8,
                    borderBottom:
                      idx === channels.length - 1
                        ? "none"
                        : "1px solid var(--color-border-subtle)",
                    fontSize: 11,
                    color: testResults[ch.channel_type].ok
                      ? "var(--color-success)"
                      : "var(--color-danger)",
                  }}
                >
                  {testResults[ch.channel_type].ok ? "✓ " : "✗ "}
                  {testResults[ch.channel_type].message}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}
