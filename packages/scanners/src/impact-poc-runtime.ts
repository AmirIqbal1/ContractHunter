import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import { type ImpactForkSession } from "@contracthunter/core";
import { ImpactForkService, type ImpactForkHandle } from "./impact-fork-service";

const execFileAsync = promisify(execFile);
const createSchema = z.object({ sessionId: z.string().uuid() }).strict();
const READ_METHODS = new Set(["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_getBalance", "eth_call"]);
const SOCKET_DESTINATION = "/run/impact/fork.sock";
const PROBE_SCHEMA = "v1";
export type ImpactPoCRuntimeStatus = "created" | "starting" | "ready" | "failed" | "stopping" | "stopped";
export type ImpactPoCRuntimeView = Readonly<{ id: string; sessionId: string; status: ImpactPoCRuntimeStatus;
  imageId: string; runtimeSchema: typeof PROBE_SCHEMA; createdAt: number; stoppedAt: number | null; failureCode: string | null }>;
type Runtime = { view: ImpactPoCRuntimeView; handle: ImpactForkHandle; tokenHash: string; directory: string;
  socketPath: string; server: Server; containerId?: string; stopping: boolean };
export type ImpactContainerInspect = { Id: string; State: { Running: boolean }; Config: { Image: string; User: string; Env: string[] };
  HostConfig: { NetworkMode: string; ReadonlyRootfs: boolean; Privileged: boolean; CapDrop: string[]; SecurityOpt: string[];
    PidsLimit: number; NanoCpus: number; Memory: number; Binds: string[] | null };
  Mounts: Array<{ Type: string; Source: string; Destination: string; RW: boolean }> };
export type ImpactContainerDriver = {
  verifyImage(imageId: string): Promise<void>;
  create(input: { runtimeId: string; sessionId: string; tokenHash: string; imageId: string; socketPath: string; groupId: number }): Promise<string>;
  start(containerId: string): Promise<void>;
  inspect(containerId: string): Promise<ImpactContainerInspect>;
  logs(containerId: string): Promise<string>;
  remove(containerId: string): Promise<void>;
  removeStale(): Promise<void>;
};

async function docker(args: string[]): Promise<string> {
  try {
    const result = await execFileAsync("/usr/bin/docker", args, { timeout: 10_000, maxBuffer: 64 * 1024,
      env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", HOME: "/nonexistent" } });
    return result.stdout.trim();
  } catch { throw new Error("impact_container_unavailable"); }
}
export class DockerImpactContainerDriver implements ImpactContainerDriver {
  async verifyImage(imageId: string): Promise<void> {
    const raw = await docker(["image", "inspect", imageId]);
    const images = JSON.parse(raw) as Array<{ Id: string; Config: { Labels?: Record<string, string> } }>;
    if (images.length !== 1 || images[0]?.Id !== imageId || images[0]?.Config.Labels?.["org.contracthunter.impact-probe-schema"] !== PROBE_SCHEMA)
      throw new Error("impact_image_untrusted");
  }
  create(input: { runtimeId: string; sessionId: string; tokenHash: string; imageId: string; socketPath: string; groupId: number }): Promise<string> {
    return docker(["create", "--name", `ch-impact-${input.runtimeId}`, "--network", "none", "--read-only",
      "--user", `10003:${input.groupId}`, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
      "--pids-limit", "32", "--cpus", "0.5", "--memory", "128m", "--memory-swap", "128m",
      "--tmpfs", "/tmp:size=16777216,mode=1770,uid=10003", "--mount",
      `type=bind,source=${input.socketPath},target=${SOCKET_DESTINATION},readonly`,
      "--label", "org.contracthunter.impact-runtime=v1", "--label", `org.contracthunter.impact-runtime-id=${input.runtimeId}`,
      "--label", `org.contracthunter.impact-session-id=${input.sessionId}`,
      "--label", `org.contracthunter.impact-token-sha256=${input.tokenHash}`, input.imageId]);
  }
  async start(containerId: string): Promise<void> { await docker(["start", containerId]); }
  async inspect(containerId: string): Promise<ImpactContainerInspect> {
    const raw = await docker(["inspect", containerId]);
    const value = JSON.parse(raw) as ImpactContainerInspect[];
    if (value.length !== 1) throw new Error("impact_container_unavailable");
    return value[0]!;
  }
  logs(containerId: string): Promise<string> { return docker(["logs", containerId]); }
  async remove(containerId: string): Promise<void> { await docker(["rm", "-f", containerId]); }
  async removeStale(): Promise<void> {
    const ids = (await docker(["ps", "-aq", "--filter", "label=org.contracthunter.impact-runtime=v1"])) .split(/\s+/).filter(Boolean);
    for (const id of ids) await this.remove(id);
  }
}
function tokenHash(handle: ImpactForkHandle): string { return createHash("sha256").update(handle.token).digest("hex"); }
function inspectIsSafe(container: ImpactContainerInspect, runtime: Runtime, groupId: number): boolean {
  const host = container.HostConfig;
  const mount = container.Mounts;
  return container.Id === runtime.containerId && container.State.Running && container.Config.Image === runtime.view.imageId &&
    container.Config.User === `10003:${groupId}` && host.NetworkMode === "none" && host.ReadonlyRootfs && !host.Privileged &&
    host.CapDrop.includes("ALL") && host.SecurityOpt.some((setting) => setting.startsWith("no-new-privileges")) &&
    host.PidsLimit === 32 && host.NanoCpus === 500_000_000 && host.Memory === 128 * 1024 * 1024 &&
    (!host.Binds || host.Binds.length === 0) && mount.length === 1 && mount[0]?.Type === "bind" &&
    mount[0]?.Source === runtime.socketPath && mount[0]?.Destination === SOCKET_DESTINATION && !mount[0]?.RW &&
    !container.Config.Env.some((entry) => /^(?:IMPACT_RPC_|OPENAI_|DATABASE_|DOCKER_|HTTP_PROXY=|HTTPS_PROXY=|ALL_PROXY=|PRIVATE_KEY=|WALLET_)/.test(entry));
}
function boundedJson(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value));
  if (body.length > 64 * 1024) throw new Error("impact_bridge_response_invalid");
  return body;
}
async function boundedRpcResponse(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw Error("local RPC unavailable");
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > 64 * 1024) throw Error("local RPC response oversized");
      chunks.push(part.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } finally { await reader.cancel().catch(() => undefined); }
}

export class ImpactPoCRuntimeService {
  private readonly runtimes = new Map<string, Runtime>();
  private initialization: Promise<void> | null = null;
  constructor(private readonly forks: ImpactForkService, private readonly resolveHandle: (sessionId: string) => ImpactForkHandle | undefined,
    private readonly imageId: string, private readonly driver: ImpactContainerDriver = new DockerImpactContainerDriver()) {
    if (!/^sha256:[0-9a-f]{64}$/.test(imageId)) throw new Error("impact_image_untrusted");
  }
  private async initialize(): Promise<void> {
    this.initialization ??= (async () => {
      await this.driver.verifyImage(this.imageId);
      await this.driver.removeStale(); // Never rebind a container left by an earlier controller process.
    })();
    try { await this.initialization; }
    catch (error) { this.initialization = null; throw error; }
  }
  get(id: string): ImpactPoCRuntimeView | null { return this.runtimes.get(id)?.view ?? null; }
  private async bridge(runtime: Runtime): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      runtime.server.once("error", reject);
      runtime.server.listen(runtime.socketPath, resolve);
    });
    chmodSync(runtime.socketPath, 0o660);
  }
  private makeServer(runtime: Runtime): Server {
    const server = createServer(async (request, response) => {
      try {
        if (request.method !== "POST" || request.url !== "/" || runtime.stopping) throw Error("bridge denied");
        const chunks: Buffer[] = []; let size = 0;
        for await (const chunk of request) { size += (chunk as Buffer).length; if (size > 64 * 1024) throw Error("oversized"); chunks.push(chunk as Buffer); }
        const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        if (!value || typeof value !== "object" || Array.isArray(value) || value.jsonrpc !== "2.0" ||
          typeof value.method !== "string" || !READ_METHODS.has(value.method) || !Array.isArray(value.params) ||
          !(typeof value.id === "number" && Number.isSafeInteger(value.id) || typeof value.id === "string" && value.id.length <= 64)) throw Error("bridge denied");
        const current = this.resolveHandle(runtime.view.sessionId);
        if (!current || tokenHash(current) !== runtime.tokenHash) throw Error("runtime token changed");
        const session = await this.forks.assertSafeImpactExecutionEndpoint(runtime.handle);
        const upstream = await fetch(session.localRpcEndpoint!, { method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify(value), signal: AbortSignal.timeout(3000), redirect: "manual" });
        if (upstream.status !== 200 || Number(upstream.headers.get("content-length") ?? 0) > 64 * 1024) throw Error("local RPC unavailable");
        const result = await boundedRpcResponse(upstream);
        response.writeHead(200, { "content-type": "application/json" }).end(boundedJson(result));
      } catch { response.writeHead(503).end(); }
    });
    server.maxConnections = 4; server.requestTimeout = 5000; server.headersTimeout = 5000;
    return server;
  }
  async create(input: unknown): Promise<ImpactPoCRuntimeView> {
    const { sessionId } = createSchema.parse(input);
    await this.initialize();
    const handle = this.resolveHandle(sessionId);
    if (!handle) throw Error("impact_session_unavailable");
    const session: ImpactForkSession = await this.forks.assertSafeImpactExecutionEndpoint(handle);
    if (session.status !== "ready" || session.id !== sessionId) throw Error("impact_session_unavailable");
    if ([...this.runtimes.values()].some((entry) => entry.view.sessionId === sessionId && entry.view.status === "ready"))
      throw Error("impact_runtime_limit");
    const id = randomUUID(); const directory = mkdtempSync(path.join(os.tmpdir(), "ch-impact-runtime-"));
    const socketPath = path.join(directory, "fork.sock");
    const view: ImpactPoCRuntimeView = { id, sessionId, status: "created", imageId: this.imageId, runtimeSchema: PROBE_SCHEMA,
      createdAt: Date.now(), stoppedAt: null, failureCode: null };
    const runtime: Runtime = { view, handle, tokenHash: tokenHash(handle), directory, socketPath, server: null as unknown as Server, stopping: false };
    runtime.server = this.makeServer(runtime);
    this.runtimes.set(id, runtime);
    try {
      runtime.view = { ...runtime.view, status: "starting" };
      await this.bridge(runtime);
      runtime.containerId = await this.driver.create({ runtimeId: id, sessionId, tokenHash: runtime.tokenHash,
        imageId: this.imageId, socketPath, groupId: process.getgid?.() ?? 0 });
      await this.driver.start(runtime.containerId);
      let safe = false;
      for (let i = 0; i < 30; i++) {
        const inspected = await this.driver.inspect(runtime.containerId);
        if (!inspectIsSafe(inspected, runtime, process.getgid?.() ?? 0)) throw Error("impact_container_unsafe");
        try {
          const log = await this.driver.logs(runtime.containerId);
          const probe = JSON.parse(log.split("\n")[0] ?? "") as Record<string, unknown>;
          if (probe.schema === "impact-probe-v1" && probe.chainId === `0x${session.chainId.toString(16)}` &&
            Array.isArray(probe.interfaces) && probe.interfaces.length === 1 && probe.interfaces[0] === "lo" &&
            Array.isArray(probe.routes) && probe.routes.length === 0 && probe.uid === 10003 &&
            probe.capEff === "0000000000000000" && probe.capBnd === "0000000000000000" &&
            probe.noNewPrivs === "1" && probe.seccomp === "2" &&
            typeof probe.appArmor === "string" && probe.appArmor !== "unconfined" &&
            probe.dockerSocket === false &&
            probe.dataDir === false && probe.verificationDir === false && probe.otherForkSocket === false &&
            Array.isArray(probe.sensitiveEnvironmentKeys) && probe.sensitiveEnvironmentKeys.length === 0) { safe = true; break; }
        } catch { /* Probe is still starting. */ }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      if (!safe) throw Error("impact_probe_failed");
      runtime.view = { ...runtime.view, status: "ready" };
      return runtime.view;
    } catch (error) {
      await this.destroy(id);
      runtime.view = { ...runtime.view, status: "failed", failureCode: error instanceof Error ? error.message.slice(0, 64) : "impact_runtime_failed" };
      throw error;
    }
  }
  async inspect(id: string): Promise<ImpactPoCRuntimeView> {
    const runtime = this.runtimes.get(id);
    if (!runtime) throw Error("impact_runtime_unavailable");
    if (runtime.view.status !== "ready" || !runtime.containerId || tokenHash(this.resolveHandle(runtime.view.sessionId) ?? { id: "", token: "" }) !== runtime.tokenHash)
      throw Error("impact_runtime_stale");
    await this.forks.assertSafeImpactExecutionEndpoint(runtime.handle);
    if (!inspectIsSafe(await this.driver.inspect(runtime.containerId), runtime, process.getgid?.() ?? 0)) throw Error("impact_container_unsafe");
    return runtime.view;
  }
  async destroy(id: string): Promise<ImpactPoCRuntimeView> {
    const runtime = this.runtimes.get(id);
    if (!runtime) throw Error("impact_runtime_unavailable");
    if (runtime.view.status === "stopped") return runtime.view;
    runtime.stopping = true;
    runtime.view = { ...runtime.view, status: "stopping" };
    let failed = false;
    if (runtime.containerId) try { await this.driver.remove(runtime.containerId); } catch { failed = true; }
    runtime.server.closeAllConnections();
    await new Promise<void>((resolve) => runtime.server.close(() => resolve()));
    rmSync(runtime.directory, { recursive: true, force: true });
    runtime.view = { ...runtime.view, status: failed ? "failed" : "stopped", stoppedAt: Date.now(),
      failureCode: failed ? "impact_container_cleanup_failed" : null };
    if (failed) throw Error("impact_container_cleanup_failed");
    return runtime.view;
  }
  async stopForSession(sessionId: string): Promise<void> {
    for (const runtime of this.runtimes.values()) if (runtime.view.sessionId === sessionId && runtime.view.status !== "stopped") await this.destroy(runtime.view.id);
  }
  async shutdown(): Promise<void> {
    for (const runtime of this.runtimes.values()) if (runtime.view.status !== "stopped") await this.destroy(runtime.view.id);
  }
}
