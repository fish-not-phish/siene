# ── Stage 1: deps ────────────────────────────────────────────────────────────
FROM oven/bun:1-alpine AS deps
WORKDIR /app

# ── Aikido Safe Chain ─────────────────────────────────────────────────────────
# Intercepts bun installs and checks packages for malware before installation.
RUN apk add --no-cache curl && \
    curl -fsSL https://github.com/AikidoSec/safe-chain/releases/download/1.5.8/install-safe-chain.sh \
    | sh -s -- --ci

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# ── Stage 2: build ───────────────────────────────────────────────────────────
FROM oven/bun:1-alpine AS builder
WORKDIR /app

# Build-time public env vars (baked into the JS bundle by Next.js)
ARG NEXT_PUBLIC_BASE_URL
ARG NEXT_PUBLIC_BASE_URL_ACCOUNTS
ARG NEXT_PUBLIC_REGISTRY_HOST

ENV NEXT_PUBLIC_BASE_URL=${NEXT_PUBLIC_BASE_URL}
ENV NEXT_PUBLIC_BASE_URL_ACCOUNTS=${NEXT_PUBLIC_BASE_URL_ACCOUNTS}
ENV NEXT_PUBLIC_REGISTRY_HOST=${NEXT_PUBLIC_REGISTRY_HOST}
ENV NEXT_TELEMETRY_DISABLED=1

# ── Aikido Safe Chain ─────────────────────────────────────────────────────────
RUN apk add --no-cache curl && \
    curl -fsSL https://github.com/AikidoSec/safe-chain/releases/download/1.5.8/install-safe-chain.sh \
    | sh -s -- --ci

COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN bun run build

# ── Stage 3: runner ───────────────────────────────────────────────────────────
# Use Node (not Bun) — Next.js standalone server.js is a Node.js script.
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser  --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["node", "server.js"]
