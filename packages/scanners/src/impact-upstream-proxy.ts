import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { assertUpstreamReadMethod } from "@contracthunter/core";

const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export function validateUpstreamPayload(raw: Buffer): void {
  if (raw.length === 0 || raw.length > MAX_REQUEST_BYTES) throw new Error("impact_upstream_request_invalid");
  let value: unknown;
  try { value = JSON.parse(raw.toString("utf8")); }
  catch { throw new Error("impact_upstream_request_invalid"); }
  const calls = Array.isArray(value) ? value : [value];
  if (calls.length < 1 || calls.length > 20) throw new Error("impact_upstream_request_invalid");
  for (const call of calls) {
    if (typeof call !== "object" || call === null || Array.isArray(call)) throw new Error("impact_upstream_request_invalid");
    const candidate = call as Record<string, unknown>;
    if (candidate.jsonrpc !== "2.0" || typeof candidate.method !== "string" || !Array.isArray(candidate.params) ||
      !(typeof candidate.id === "string" || typeof candidate.id === "number" || candidate.id === null)) throw new Error("impact_upstream_request_invalid");
    assertUpstreamReadMethod(candidate.method);
  }
}

async function boundedResponse(response: Response): Promise<Buffer> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("impact_upstream_response_invalid");
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > MAX_RESPONSE_BYTES) throw new Error("impact_upstream_response_oversized");
      chunks.push(part.value);
    }
    return Buffer.concat(chunks);
  } finally { await reader.cancel().catch(() => undefined); }
}

export type ReadOnlyUpstreamProxy = { readonly url: string; close(): Promise<void> };

export async function forwardApprovedUpstreamRequest(upstreamUrl: URL, body: Buffer, fetchImpl: typeof fetch): Promise<{ status: number; body: Buffer }> {
  validateUpstreamPayload(body);
  const forwarded = await fetchImpl(upstreamUrl, { method: "POST", headers: { "content-type": "application/json" }, body: new Uint8Array(body),
    redirect: "manual", signal: AbortSignal.timeout(10_000) });
  if (forwarded.status >= 300 && forwarded.status < 400) throw new Error("impact_upstream_redirect_refused");
  return { status: forwarded.status, body: await boundedResponse(forwarded) };
}

export async function startReadOnlyUpstreamProxy(upstreamUrl: string, fetchImpl: typeof fetch = fetch): Promise<ReadOnlyUpstreamProxy> {
  let parsed: URL;
  try { parsed = new URL(upstreamUrl); }
  catch { throw new Error("impact_upstream_unavailable"); }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.hash) throw new Error("impact_upstream_unavailable");
  const token = randomBytes(24).toString("hex");
  let active = 0;
  const server: Server = createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== `/${token}` || active >= 8) {
      response.writeHead(403).end(); return;
    }
    active++;
    try {
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += (chunk as Buffer).length;
        if (bytes > MAX_REQUEST_BYTES) throw new Error("impact_upstream_request_invalid");
        chunks.push(chunk as Buffer);
      }
      const body = Buffer.concat(chunks);
      const forwarded = await forwardApprovedUpstreamRequest(parsed, body, fetchImpl); // Reject the whole batch before any forwarding.
      response.writeHead(forwarded.status, { "content-type": "application/json" }).end(forwarded.body);
    } catch (error) {
      const forbidden = error instanceof Error && error.message === "impact_upstream_method_forbidden";
      response.writeHead(forbidden ? 403 : 502).end();
    } finally { active--; }
  });
  server.maxConnections = 8;
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  try {
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    const address = server.address();
    if (!address || typeof address === "string" || address.address !== "127.0.0.1") throw new Error("impact_upstream_unavailable");
    return { url: `http://127.0.0.1:${address.port}/${token}`, close: () => new Promise<void>((resolve) => {
      server.closeAllConnections(); server.close(() => resolve());
    }) };
  } catch (error) { server.close(); throw error; }
}
