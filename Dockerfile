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

FROM node:22-bookworm-slim AS aderyn
ARG ADERYN_VERSION=0.6.8
ARG TARGETARCH
ADD --checksum=sha256:ffd6ca658962e211a3ac821c646f69c8e14bf1b1001cbfe091bcd4535a691e46 https://github.com/Cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-x86_64-unknown-linux-gnu.tar.xz /tmp/aderyn-amd64.tar.xz
ADD --checksum=sha256:961070bf5ee4ed0f82f67a261c616e1525ec1b036bae60cdaec94d087eb5e405 https://github.com/Cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-aarch64-unknown-linux-gnu.tar.xz /tmp/aderyn-arm64.tar.xz
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils \
  && case "${TARGETARCH}" in amd64) archive=/tmp/aderyn-amd64.tar.xz; directory=aderyn-x86_64-unknown-linux-gnu ;; arm64) archive=/tmp/aderyn-arm64.tar.xz; directory=aderyn-aarch64-unknown-linux-gnu ;; *) exit 1 ;; esac \
  && tar -xJf "${archive}" -C /tmp \
  && install -m 0755 "/tmp/${directory}/aderyn" /usr/local/bin/aderyn \
  && test "$(aderyn --version)" = "aderyn ${ADERYN_VERSION}"

FROM node:22-bookworm-slim AS foundry
ARG FOUNDRY_VERSION=1.7.1
ARG TARGETARCH
ADD --checksum=sha256:cf7e688ed0c4c48adffca788b496076e31060b67ac5afe1e43dbb5499c20c88b https://github.com/foundry-rs/foundry/releases/download/v1.7.1/foundry_v1.7.1_linux_amd64.tar.gz /tmp/foundry-amd64.tar.gz
ADD --checksum=sha256:c8fe8fa09ae3aba2c81b510c6f9da3a9d468029b9580e690b245b3f0aea687ae https://github.com/foundry-rs/foundry/releases/download/v1.7.1/foundry_v1.7.1_linux_arm64.tar.gz /tmp/foundry-arm64.tar.gz
RUN case "${TARGETARCH}" in amd64) archive=/tmp/foundry-amd64.tar.gz ;; arm64) archive=/tmp/foundry-arm64.tar.gz ;; *) exit 1 ;; esac \
  && tar -xzf "${archive}" -C /tmp forge \
  && install -m 0755 /tmp/forge /usr/local/bin/forge \
  && forge --version

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
ENV ADERYN_TIMEOUT_MS=300000
ENV SCANNER_MAX_OUTPUT_BYTES=20971520
ENV SOLC_INSTALL_TIMEOUT_MS=120000
ENV MAX_SOLC_VERSIONS_PER_SCAN=8
ENV ALLOW_COMPILER_DOWNLOADS=true
ENV AI_ENABLED=false
ENV OPENAI_MODEL=gpt-5-mini
ENV AI_INPUT_COST_PER_MILLION_USD=0.25
ENV AI_OUTPUT_COST_PER_MILLION_USD=2.00
ENV AI_TIMEOUT_MS=180000
ENV AI_MAX_SOURCE_BYTES=500000
ENV AI_MAX_FILES=120
ENV AI_MAX_FILE_BYTES=75000
ENV AI_REVIEW_MAX_SOURCE_BYTES=300000
ENV AI_REVIEW_MAX_FILES=80
ENV AI_MAX_REVIEWERS=10
ENV AI_REVIEW_CONCURRENCY=2
ENV AI_REVIEW_TIMEOUT_MS=180000
ENV AI_REVIEW_MAX_TOTAL_REQUESTS=12
ENV AI_VERIFICATION_PLAN_TIMEOUT_MS=120000
ENV AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES=120000
ENV AI_VERIFICATION_PLAN_MAX_FILES=12
ENV TOOL_HOME_DIR=/data/tool-home
ENV PATH="/usr/local/bin:/opt/slither/bin:${PATH}"
COPY docker/solc-select-wrapper.py /usr/local/bin/solc-select
COPY --from=aderyn /usr/local/bin/aderyn /usr/local/bin/aderyn
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates python3 python3-venv && rm -rf /var/lib/apt/lists/* \
  && python3 -m venv /opt/slither \
  && /opt/slither/bin/pip install --no-cache-dir "slither-analyzer==${SLITHER_VERSION}" \
  && chmod 755 /usr/local/bin/solc-select \
  && git --version \
  && npm --version \
  && slither --version \
  && aderyn --version \
  && forge --version \
  && solc-select --version \
  && mkdir -p /data/repositories /data/tool-home /home/node \
  && chown -R node:node /data /home/node
COPY --from=builder --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "apps/web/server.js"]
