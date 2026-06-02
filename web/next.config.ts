import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Pin the workspace root so the stray lockfile in $HOME isn't picked as root.
  turbopack: {
    root: path.join(__dirname),
  },
};

export default nextConfig;
