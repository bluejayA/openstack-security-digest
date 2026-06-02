"use client";

import { useCallback, useState } from "react";
import useSWR from "swr";
import {
  getSecurity,
  getDeliveries,
  type SecurityResponse,
  type Delivery,
} from "@/lib/api";
import { IMPACT_ORDER, IMPACT_STYLES } from "@/lib/impact";
import type { Impact } from "@/lib/api";
import { AdvisoryCard } from "@/components/advisory-card";
import { ImpactBadge } from "@/components/impact-badge";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const WEEK_OPTIONS = [
  { value: "1", label: "Latest week" },
  { value: "4", label: "Last 4 weeks" },
  { value: "12", label: "Last 12 weeks" },
  { value: "20", label: "All available" },
];

interface DashboardData {
  sec: SecurityResponse;
  dels: Delivery[];
}

export default function DashboardPage() {
  const [weeks, setWeeks] = useState("1");

  // SWR keys off `weeks`; changing it (or calling mutate) triggers a refetch and
  // flips isValidating, which drives the refresh spinner.
  const { data, error, isLoading, isValidating, mutate } =
    useSWR<DashboardData>(
      ["security", weeks],
      async (): Promise<DashboardData> => {
        const [sec, dels] = await Promise.all([
          getSecurity({ weeks: Number(weeks) }),
          getDeliveries(20).catch(() => [] as Delivery[]),
        ]);
        return { sec, dels };
      },
      { revalidateOnFocus: false },
    );

  const sec = data?.sec ?? null;
  const deliveries = data?.dels ?? [];

  const refresh = useCallback(() => {
    mutate();
  }, [mutate]);

  const onWeeksChange = useCallback((v: string | null) => {
    if (v) setWeeks(v);
  }, []);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Security Advisories
          </h1>
          <p className="text-sm text-muted-foreground">
            OpenStack mailing-list security items, categorized by operational
            impact.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={weeks} onValueChange={onWeeksChange}>
            <SelectTrigger className="w-[160px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {WEEK_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={refresh} disabled={isValidating}>
            {isValidating ? "Refreshing…" : "Refresh"}
          </Button>
        </div>
      </div>

      {error && (
        <Card className="border-red-500/50 bg-red-500/5 p-4 text-sm text-red-600">
          Failed to reach the API: {error.message}. Is the Go server running on{" "}
          <code className="font-mono">localhost:8080</code>?
        </Card>
      )}

      {isLoading && !sec ? (
        <LoadingState />
      ) : sec ? (
        <>
          <TotalsRow data={sec} />
          <Groups data={sec} />
          <div className="grid gap-6 md:grid-cols-2">
            <Timeline data={sec} />
            <Deliveries deliveries={deliveries} />
          </div>
        </>
      ) : null}
    </div>
  );
}

function TotalsRow({ data }: { data: SecurityResponse }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {(["Critical", "High", "Medium", "Low"] as Impact[]).map((imp) => (
        <Card key={imp} className="relative overflow-hidden p-4">
          <div
            className={`absolute left-0 top-0 h-full w-1 ${IMPACT_STYLES[imp].bar}`}
          />
          <div className="pl-2">
            <div className="text-3xl font-bold">{data.totals[imp] ?? 0}</div>
            <div className="text-sm text-muted-foreground">{imp}</div>
          </div>
        </Card>
      ))}
    </div>
  );
}

function Groups({ data }: { data: SecurityResponse }) {
  const visible = IMPACT_ORDER.filter((imp) => (data.groups[imp] ?? []).length);
  if (data.count === 0) {
    return (
      <Card className="p-10 text-center text-muted-foreground">
        No security advisories found in this window. 🎉
      </Card>
    );
  }
  return (
    <div className="space-y-8">
      {visible.map((imp) => (
        <section key={imp} className="space-y-3">
          <div className="flex items-center gap-2">
            <ImpactBadge impact={imp} />
            <h2 className="text-lg font-semibold">{imp}</h2>
            <span className="text-sm text-muted-foreground">
              ({data.groups[imp]!.length})
            </span>
          </div>
          <div className="grid gap-3">
            {data.groups[imp]!.map((a, i) => (
              <AdvisoryCard key={`${a.id}-${i}`} advisory={a} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function Timeline({ data }: { data: SecurityResponse }) {
  const RANK_IMPACT: Record<number, Impact> = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Unknown",
  };
  return (
    <Card className="p-5">
      <h3 className="mb-4 font-semibold">Weekly timeline</h3>
      <ul className="space-y-2">
        {data.digests.map((d) => (
          <li
            key={d.date}
            className="flex items-center justify-between gap-2 text-sm"
          >
            <a
              href={d.link}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-muted-foreground hover:text-foreground hover:underline"
            >
              {d.date}
            </a>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">
                {d.count} {d.count === 1 ? "item" : "items"}
              </span>
              {d.count > 0 && (
                <span
                  className={`h-2 w-2 rounded-full ${IMPACT_STYLES[RANK_IMPACT[d.topRank]].bar}`}
                  title={RANK_IMPACT[d.topRank]}
                />
              )}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function Deliveries({ deliveries }: { deliveries: Delivery[] }) {
  return (
    <Card className="p-5">
      <h3 className="mb-4 font-semibold">Recent Slack deliveries</h3>
      {deliveries.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No notifications sent yet. Configure a webhook in Settings.
        </p>
      ) : (
        <ul className="space-y-2">
          {deliveries.map((d) => (
            <li
              key={d.key}
              className="flex items-center justify-between gap-2 text-sm"
            >
              <div className="flex items-center gap-2">
                <ImpactBadge impact={d.impact} className="text-xs" />
                <span className="font-mono">{d.advisoryId || d.component}</span>
              </div>
              <span
                className={
                  d.status === "sent" ? "text-emerald-600" : "text-red-600"
                }
              >
                {d.status}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function LoadingState() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <Skeleton key={i} className="h-28" />
      ))}
    </div>
  );
}
