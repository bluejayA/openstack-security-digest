import { Badge } from "@/components/ui/badge";
import { IMPACT_STYLES } from "@/lib/impact";
import type { Impact } from "@/lib/api";
import { cn } from "@/lib/utils";

export function ImpactBadge({
  impact,
  className,
}: {
  impact: Impact;
  className?: string;
}) {
  return (
    <Badge className={cn(IMPACT_STYLES[impact]?.badge, className)}>
      {impact}
    </Badge>
  );
}
