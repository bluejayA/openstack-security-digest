import { Card } from "@/components/ui/card";
import { ImpactBadge } from "@/components/impact-badge";
import { IMPACT_STYLES } from "@/lib/impact";
import type { Advisory } from "@/lib/api";

export function AdvisoryCard({ advisory }: { advisory: Advisory }) {
  const style = IMPACT_STYLES[advisory.impact];
  const cves = advisory.cves ?? [];
  const affected = advisory.affected ?? [];

  return (
    <Card className="relative overflow-hidden p-0">
      <div className={`absolute left-0 top-0 h-full w-1 ${style?.bar}`} />
      <div className="space-y-3 p-5 pl-6">
        <div className="flex flex-wrap items-center gap-2">
          <ImpactBadge impact={advisory.impact} />
          {advisory.id && (
            <span className="font-mono text-sm font-semibold">
              {advisory.id}
            </span>
          )}
          {advisory.component && (
            <span className="text-sm text-muted-foreground">
              · {advisory.component}
            </span>
          )}
          <span className="ml-auto text-xs text-muted-foreground">
            {advisory.digestDate}
          </span>
        </div>

        <p className="text-sm leading-relaxed text-foreground/90">
          {advisory.summary}
        </p>

        {cves.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {cves.map((cve) => (
              <span
                key={cve}
                className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground"
              >
                {cve}
              </span>
            ))}
          </div>
        )}

        {affected.length > 0 && (
          <div className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground/70">Affected: </span>
            {affected.join(", ")}
          </div>
        )}

        {advisory.link && (
          <a
            href={advisory.link}
            target="_blank"
            rel="noreferrer"
            className="inline-block text-xs font-medium text-primary hover:underline"
          >
            Advisory ↗
          </a>
        )}
      </div>
    </Card>
  );
}
