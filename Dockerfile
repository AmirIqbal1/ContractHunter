FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
COPY apps/web/package.json apps/web/package.json
COPY packages/core/package.json packages/core/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/scanners/package.json packages/scanners/package.json
RUN npm ci

FROM node:22-bookworm-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
ENV DATA_DIR=/app/data
ENV REPOSITORY_DIR=/app/data/repositories
ENV DATABASE_PATH=/app/data/contracthunter.db
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-bookworm-slim AS runner
WORKDIR /app
ARG SLITHER_VERSION=0.11.3
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
ENV DATA_DIR=/data
ENV REPOSITORY_DIR=/data/repositories
ENV DATABASE_PATH=/data/contracthunter.db
ENV GIT_CLONE_TIMEOUT_MS=120000
ENV SLITHER_TIMEOUT_MS=300000
ENV SCANNER_MAX_OUTPUT_BYTES=20971520
ENV PATH="/opt/slither/bin:${PATH}"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates python3 python3-venv && rm -rf /var/lib/apt/lists/* \
  && python3 -m venv /opt/slither \
  && /opt/slither/bin/pip install --no-cache-dir "slither-analyzer==${SLITHER_VERSION}" \
  && slither --version \
  && mkdir -p /data/repositories /home/node \
  && chown -R node:node /data /home/node
COPY --from=builder --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "apps/web/server.js"]
