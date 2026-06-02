"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  getSettings,
  saveSettings,
  testSend,
  type Settings,
  type Impact,
} from "@/lib/api";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const THRESHOLDS: { value: Impact; label: string }[] = [
  { value: "Critical", label: "Critical only" },
  { value: "High", label: "High and above" },
  { value: "Medium", label: "Medium and above" },
  { value: "Low", label: "All (Low and above)" },
];

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    getSettings()
      .then(setSettings)
      .catch((e) =>
        setLoadError(e instanceof Error ? e.message : "Failed to load"),
      );
  }, []);

  function update<K extends keyof Settings>(key: K, value: Settings[K]) {
    setSettings((s) => (s ? { ...s, [key]: value } : s));
  }

  async function onSave() {
    if (!settings) return;
    setSaving(true);
    try {
      const saved = await saveSettings(settings);
      setSettings(saved);
      toast.success("Settings saved");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function onTest() {
    setTesting(true);
    try {
      await testSend();
      toast.success("Test message sent to Slack");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Test send failed");
    } finally {
      setTesting(false);
    }
  }

  if (loadError) {
    return (
      <Card className="border-red-500/50 bg-red-500/5 p-4 text-sm text-red-600">
        Failed to reach the API: {loadError}. Is the Go server running on{" "}
        <code className="font-mono">localhost:8080</code>?
      </Card>
    );
  }

  if (!settings) {
    return <p className="text-muted-foreground">Loading settings…</p>;
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Configure Slack notifications and the dashboard default window.
        </p>
      </div>

      <Card className="space-y-6 p-6">
        <div className="space-y-2">
          <Label htmlFor="webhook">Slack Incoming Webhook URL</Label>
          <Input
            id="webhook"
            type="url"
            placeholder="https://hooks.slack.com/services/…"
            value={settings.webhookUrl}
            onChange={(e) => update("webhookUrl", e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            Notable advisories are pushed here when a new digest is published.
          </p>
        </div>

        <Separator />

        <div className="grid gap-6 sm:grid-cols-2">
          <div className="space-y-2">
            <Label>Notify threshold</Label>
            <Select
              value={settings.threshold}
              onValueChange={(v) => v && update("threshold", v as Impact)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {THRESHOLDS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Minimum impact level that triggers a Slack alert.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="poll">Poll interval (minutes)</Label>
            <Input
              id="poll"
              type="number"
              min={1}
              value={settings.pollMinutes}
              onChange={(e) =>
                update("pollMinutes", Number(e.target.value) || 1)
              }
            />
            <p className="text-xs text-muted-foreground">
              How often to check the feed for a new digest.
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="scope">Default dashboard window (weeks)</Label>
            <Input
              id="scope"
              type="number"
              min={1}
              value={settings.scopeWeeks}
              onChange={(e) =>
                update("scopeWeeks", Number(e.target.value) || 1)
              }
            />
          </div>

          <div className="flex items-center justify-between rounded-lg border p-3">
            <div>
              <Label htmlFor="enabled" className="cursor-pointer">
                Auto-push enabled
              </Label>
              <p className="text-xs text-muted-foreground">
                Turn Slack notifications on.
              </p>
            </div>
            <Switch
              id="enabled"
              checked={settings.enabled}
              onCheckedChange={(v) => update("enabled", v)}
            />
          </div>
        </div>

        <Separator />

        <div className="flex flex-wrap gap-3">
          <Button onClick={onSave} disabled={saving}>
            {saving ? "Saving…" : "Save settings"}
          </Button>
          <Button
            variant="outline"
            onClick={onTest}
            disabled={testing || !settings.webhookUrl}
          >
            {testing ? "Sending…" : "Send test message"}
          </Button>
        </div>
      </Card>
    </div>
  );
}
