import type { Impact } from "@/lib/api";

export const IMPACT_ORDER: Impact[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Unknown",
];

// Tailwind utility classes per impact, tuned for light/dark.
export const IMPACT_STYLES: Record<
  Impact,
  { badge: string; bar: string; text: string }
> = {
  Critical: {
    badge: "bg-red-600 text-white border-transparent",
    bar: "bg-red-600",
    text: "text-red-600",
  },
  High: {
    badge: "bg-orange-500 text-white border-transparent",
    bar: "bg-orange-500",
    text: "text-orange-500",
  },
  Medium: {
    badge: "bg-amber-400 text-black border-transparent",
    bar: "bg-amber-400",
    text: "text-amber-500",
  },
  Low: {
    badge: "bg-emerald-600 text-white border-transparent",
    bar: "bg-emerald-600",
    text: "text-emerald-600",
  },
  Unknown: {
    badge: "bg-slate-500 text-white border-transparent",
    bar: "bg-slate-500",
    text: "text-slate-500",
  },
};
