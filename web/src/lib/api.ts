// API client + types for the OpenStack Security Digest Go backend.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8080";

export type Impact = "Critical" | "High" | "Medium" | "Low" | "Unknown";

export interface Advisory {
  id: string;
  kind: string;
  component: string;
  cves: string[] | null;
  affected: string[] | null;
  summary: string; // display language (Korean when translation is enabled)
  summaryEn?: string; // original English text
  link: string;
  impact: Impact;
  // enrichment from the API
  digestTitle: string;
  digestLink: string;
  digestDate: string;
}

export interface DigestSummary {
  title: string;
  link: string;
  date: string;
  count: number;
  topRank: number;
}

export interface SecurityResponse {
  generatedAt: string;
  scope: Record<string, unknown>;
  count: number;
  totals: Partial<Record<Impact, number>>;
  groups: Partial<Record<Impact, Advisory[]>>;
  digests: DigestSummary[];
}

export interface Settings {
  webhookUrl: string;
  threshold: Impact;
  pollMinutes: number;
  scopeWeeks: number;
  enabled: boolean;
}

export interface Delivery {
  key: string;
  digestGuid: string;
  advisoryId: string;
  component: string;
  impact: Impact;
  sentAt: string;
  status: string;
  error?: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body?.error) detail = body.error;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export function getSecurity(params: {
  weeks?: number;
  from?: string;
  to?: string;
}): Promise<SecurityResponse> {
  const q = new URLSearchParams();
  if (params.from) q.set("from", params.from);
  if (params.to) q.set("to", params.to);
  if (params.weeks && !params.from) q.set("weeks", String(params.weeks));
  return req<SecurityResponse>(`/api/security?${q.toString()}`);
}

export function getSettings(): Promise<Settings> {
  return req<Settings>("/api/settings");
}

export function saveSettings(s: Settings): Promise<Settings> {
  return req<Settings>("/api/settings", {
    method: "PUT",
    body: JSON.stringify(s),
  });
}

export function testSend(): Promise<{ status: string }> {
  return req<{ status: string }>("/api/settings/test", { method: "POST" });
}

export function notifyNow(): Promise<{
  sent: number;
  digest?: string;
  message?: string;
}> {
  return req("/api/notify", { method: "POST" });
}

export function getDeliveries(limit = 50): Promise<Delivery[]> {
  return req<Delivery[]>(`/api/deliveries?limit=${limit}`);
}
