FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436
LABEL org.contracthunter.impact-probe-schema="v1"
RUN mkdir -p /run/impact /probe && chmod 0755 /run/impact /probe
COPY probe.mjs /probe/probe.mjs
USER 10003:10003
CMD ["node", "/probe/probe.mjs"]
