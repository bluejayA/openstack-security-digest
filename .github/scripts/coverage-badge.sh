#!/usr/bin/env bash
# Generate a self-hosted coverage badge SVG (no external service / no shields.io).
# Usage: coverage-badge.sh <percent> <out.svg>   e.g. coverage-badge.sh 79.7 coverage.svg
set -euo pipefail

pct="${1:?usage: coverage-badge.sh <percent> <out.svg>}"
out="${2:?usage: coverage-badge.sh <percent> <out.svg>}"

# Pick a color by threshold (float compare via awk, no bc dependency).
color="$(awk -v p="$pct" 'BEGIN{
  if      (p>=90) print "#4c1";
  else if (p>=80) print "#97ca00";
  else if (p>=70) print "#a4a61d";
  else if (p>=60) print "#dfb317";
  else            print "#e05d44";
}')"

label="coverage"
value="${pct}%"

cat > "$out" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="114" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="114" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="63" height="20" fill="#555"/>
    <rect x="63" width="51" height="20" fill="${color}"/>
    <rect width="114" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="32" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="32" y="14">${label}</text>
    <text x="88" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="88" y="14">${value}</text>
  </g>
</svg>
SVG

echo "wrote ${out} (${value}, ${color})"
