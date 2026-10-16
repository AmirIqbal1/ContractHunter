export async function boundedImpactJson(request: Request, limit = 20 * 1024): Promise<unknown> {
  if (!request.body || Number(request.headers.get("content-length") ?? 0) > limit) throw Error("invalid_body");
  const reader = request.body.getReader();
  const parts: Uint8Array[] = []; let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > limit) throw Error("invalid_body");
      parts.push(part.value);
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(parts))) as unknown;
  } finally { await reader.cancel().catch(() => undefined); }
}
