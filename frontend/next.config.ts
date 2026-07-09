import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Produces a self-contained .next/standalone directory used by the Docker image.
  // Has no effect in `bun dev` — safe to keep on permanently.
  output: "standalone",

  // In the Docker container, server-side fetch calls that hit /api/* should be
  // forwarded to the backend service on the internal Docker network.
  // NEXT_INTERNAL_API_URL is only set inside the container (via docker-compose
  // environment); in dev it is unset so rewrites are a no-op.
  async rewrites() {
    const internalApi = process.env.NEXT_INTERNAL_API_URL;
    if (!internalApi) return [];
    return [
      {
        source: "/api/:path*",
        destination: `${internalApi}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
