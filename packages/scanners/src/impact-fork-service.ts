import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readlinkSync, readdirSync, realpathSync } from "node:fs";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { impactAddressSchema, impactForkConfigSchema, impactHashSchema, assertLocalImpactMethod, type ImpactForkConfig, type ImpactForkSession } from "@contracthunter/core";
import { runObservedProcess } from "./process-runner";
import { startReadOnlyUpstreamProxy, type ReadOnlyUpstreamProxy } from "./impact-upstream-proxy";

const HOST = "127.0.0.1";
const STARTUP_MS = 15_000;
const MAX_RUNTIME_MS = 30 * 60_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_SESSION_RECORDS = 100;

export class ImpactForkError extends Error {
  constructor(readonly code: string) { super(code); this.name = "ImpactForkError"; }
}

export type ImpactForkHandle = Readonly<{ id: string; token: string }>;
type OwnedProcess = Pick<ChildProcess, "pid" | "exitCode" | "killed" | "on" | "once" | "stdout" | "stderr">;
type Runtime = { view: ImpactForkSession; handle: ImpactForkHandle; child?: OwnedProcess; startToken?: string;
  proxy?: ReadOnlyUpstreamProxy; port?: number; snapshots: string[]; timer?: NodeJS.Timeout; stopping: boolean };
type Binary = { path: string; version: string; sha256: string };
type Dependencies = {
  resolveBinary?: () => Promise<Binary>;
  resolveUpstream?: (ref: string) => string | undefined;
  startProxy?: (url: string) => Promise<ReadOnlyUpstreamProxy>;
  launch?: (binary: Binary, args: string[]) => OwnedProcess;
  reservePort?: () => Promise<number>;
  rpc?: (endpoint: string, method: string, params: unknown[]) => Promise<unknown>;
  processToken?: (pid: number) => string;
  ownsPort?: (pid: number, port: number) => boolean;
  terminate?: (pid: number) => Promise<void>;
  onStatus?: (session: ImpactForkSession) => void;
};

function copySession(view: ImpactForkSession): ImpactForkSession {
  return { ...view, targetContracts: [...view.targetContracts], disposableAccounts: [...view.disposableAccounts] };
}

export function anvilArguments(config: ImpactForkConfig, port: number, proxyUrl: string): string[] {
  if (config.localBindAddress !== HOST || !Number.isInteger(port) || port < 1024 || port > 65535 || !proxyUrl.startsWith(`http://${HOST}:`)) throw new ImpactForkError("impact_invocation_invalid");
  return ["--host", HOST, "--port", String(port), "--fork-url", proxyUrl, "--fork-block-number", String(config.forkBlock),
    "--chain-id", String(config.chainId), "--accounts", "1", "--silent"];
}

export async function resolveTrustedAnvil(): Promise<Binary> {
  const candidates = ["/usr/local/bin/anvil", path.join(os.homedir(), ".foundry", "bin", "anvil")];
  for (const candidate of candidates) {
    try {
      const stat = lstatSync(candidate);
      if (!stat.isFile() || stat.isSymbolicLink() || !(stat.mode & 0o111) || (stat.mode & 0o022) ||
        ![0, process.getuid?.()].includes(stat.uid) || stat.size > 100 * 1024 * 1024 || realpathSync(candidate) !== candidate) continue;
      let directory = path.dirname(candidate), safeParents = true;
      while (directory !== path.dirname(directory)) {
        const parent = lstatSync(directory);
        if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o022)) { safeParents = false; break; }
        directory = path.dirname(directory);
      }
      if (!safeParents) continue;
      const sha256 = createHash("sha256").update(readFileSync(candidate)).digest("hex");
      const result = await runObservedProcess({ command: candidate, args: ["--version"], timeoutMs: 5_000, maxOutputBytes: 1_024,
        env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C" }, killProcessTree: true });
      const version = result.stdout.trim() || result.stderr.trim();
      if (result.exitCode === 0 && !result.timedOut && !result.stdoutTruncated && !result.stderrTruncated && /^anvil\s+(?:Version:\s*)?[0-9][a-zA-Z0-9.+ ()-]{0,100}$/i.test(version)) return { path: candidate, version, sha256 };
    } catch { /* Try the next approved path. */ }
  }
  throw new ImpactForkError("impact_anvil_unavailable");
}

async function reserveLoopbackPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, HOST, resolve); });
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (!address || typeof address === "string" || address.address !== HOST || address.port < 1024) throw new ImpactForkError("impact_port_unavailable");
  return address.port;
}

function launchOwnedAnvil(binary: Binary, args: string[]): OwnedProcess {
  if (process.platform !== "linux" || !existsSync("/usr/bin/setpriv")) throw new ImpactForkError("impact_process_supervision_unavailable");
  // setpriv execs Anvil and asks the kernel to kill it if the server process dies.
  return spawn("/usr/bin/setpriv", ["--pdeathsig", "SIGKILL", "--", binary.path, ...args], {
    shell: false, detached: true, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C", NO_COLOR: "1" },
  });
}

function processStartToken(pid: number): string {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
  const start = fields[19];
  if (!start || !/^\d+$/.test(start)) throw new ImpactForkError("impact_process_identity_lost");
  return start;
}

function processOwnsLoopbackPort(pid: number, port: number): boolean {
  const portHex = port.toString(16).toUpperCase().padStart(4, "0");
  const lines = readFileSync("/proc/net/tcp", "utf8").split("\n");
  const inodes = new Set(lines.slice(1).map((line) => line.trim().split(/\s+/)).filter((fields) =>
    fields[1] === `0100007F:${portHex}` && fields[3] === "0A").map((fields) => fields[9]));
  if (!inodes.size) return false;
  return readdirSync(`/proc/${pid}/fd`).some((fd) => {
    try { const match = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${pid}/fd/${fd}`)); return Boolean(match && inodes.has(match[1])); }
    catch { return false; }
  });
}

async function terminateGroup(pid: number): Promise<void> {
  try { process.kill(-pid, "SIGTERM"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
  await new Promise((resolve) => setTimeout(resolve, 300));
  try { process.kill(-pid, "SIGKILL"); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
}

async function rpcCall(endpoint: string, method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), redirect: "manual", signal: AbortSignal.timeout(3_000) });
  if (response.status !== 200 || Number(response.headers.get("content-length") ?? 0) > 64 * 1024) throw new ImpactForkError("impact_rpc_unavailable");
  const reader = response.body?.getReader();
  if (!reader) throw new ImpactForkError("impact_rpc_invalid");
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > 64 * 1024) throw new ImpactForkError("impact_rpc_invalid");
      chunks.push(part.value);
    }
  } finally { await reader.cancel().catch(() => undefined); }
  const raw = Buffer.concat(chunks).toString("utf8");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new ImpactForkError("impact_rpc_invalid"); }
  if (typeof value !== "object" || value === null || (value as { error?: unknown }).error || !("result" in value)) throw new ImpactForkError("impact_rpc_invalid");
  return (value as { result: unknown }).result;
}

function hexNumber(value: unknown): number {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) throw new ImpactForkError("impact_rpc_invalid");
  const result = Number(BigInt(value));
  if (!Number.isSafeInteger(result)) throw new ImpactForkError("impact_rpc_invalid");
  return result;
}

function blockIdentity(value: unknown, number: number): string {
  if (!value || typeof value !== "object") throw new ImpactForkError("impact_fork_block_mismatch");
  const block = value as { number?: unknown; hash?: unknown };
  if (hexNumber(block.number) !== number || !impactHashSchema.safeParse(block.hash).success) throw new ImpactForkError("impact_fork_block_mismatch");
  return (block.hash as string).toLowerCase();
}

export class ImpactForkService {
  private readonly sessions = new Map<string, Runtime>();
  private readonly reservedPorts = new Set<number>();
  constructor(private readonly deps: Dependencies = {}) {}

  private publish(runtime: Runtime, update: Partial<ImpactForkSession>): void {
    runtime.view = { ...runtime.view, ...update };
    this.deps.onStatus?.(copySession(runtime.view));
  }

  createForkSession(input: unknown): ImpactForkHandle {
    const config = impactForkConfigSchema.parse(input);
    if (this.sessions.size >= MAX_SESSION_RECORDS) {
      for (const [id, runtime] of this.sessions) {
        if (runtime.view.status === "stopped") { this.sessions.delete(id); break; }
      }
      if (this.sessions.size >= MAX_SESSION_RECORDS) throw new ImpactForkError("impact_session_limit");
    }
    if ([...this.sessions.values()].filter((s) => s.view.status === "starting" || s.view.status === "ready").length >= 2) throw new ImpactForkError("impact_session_limit");
    const handle = Object.freeze({ id: randomUUID(), token: randomBytes(32).toString("hex") });
    const view: ImpactForkSession = { id: handle.id, status: "created", findingId: config.findingId ?? null, hypothesisId: config.hypothesisId ?? null,
      chainId: config.chainId, network: config.network, upstreamRpcRef: config.upstreamRpcRef, targetContracts: config.targetContracts,
      resolvedForkBlock: config.forkBlock, historicalTransactionHash: config.historicalTransactionHash ?? null,
      forkBlockHash: null, localPort: null, localRpcEndpoint: null, anvilVersion: null, anvilSha256: null,
      processPid: null, baselineSnapshotId: null, disposableAccounts: [], createdAt: Date.now(), startedAt: null, stoppedAt: null, failureCode: null };
    this.sessions.set(handle.id, { view, handle, snapshots: [], stopping: false });
    try { this.deps.onStatus?.(copySession(view)); }
    catch (error) { this.sessions.delete(handle.id); throw error; }
    return handle;
  }

  getSession(id: string): ImpactForkSession | null { const view = this.sessions.get(id)?.view; return view ? copySession(view) : null; }

  private requireHandle(handle: ImpactForkHandle): Runtime {
    const runtime = this.sessions.get(handle.id);
    if (!runtime || runtime.handle.token !== handle.token) throw new ImpactForkError("impact_session_identity_invalid");
    return runtime;
  }

  async startForkSession(handle: ImpactForkHandle, signal?: AbortSignal): Promise<ImpactForkSession> {
    const runtime = this.requireHandle(handle);
    if (runtime.view.status !== "created") throw new ImpactForkError("impact_transition_invalid");
    if ([...this.sessions.values()].filter((s) => s !== runtime && (s.view.status === "starting" || s.view.status === "ready")).length >= 2) throw new ImpactForkError("impact_session_limit");
    this.publish(runtime, { status: "starting" });
    const config = impactForkConfigSchema.parse({ chainId: runtime.view.chainId, network: runtime.view.network,
      upstreamRpcRef: runtime.view.upstreamRpcRef, targetContracts: runtime.view.targetContracts,
      forkBlock: runtime.view.resolvedForkBlock, findingId: runtime.view.findingId ?? undefined,
      hypothesisId: runtime.view.hypothesisId ?? undefined, historicalTransactionHash: runtime.view.historicalTransactionHash ?? undefined, localBindAddress: HOST });
    try {
      if (signal?.aborted) throw new ImpactForkError("impact_startup_cancelled");
      const binary = await (this.deps.resolveBinary ?? resolveTrustedAnvil)();
      if (signal?.aborted) throw new ImpactForkError("impact_startup_cancelled");
      const upstream = (this.deps.resolveUpstream ?? ((ref: string) => process.env[ref]))(config.upstreamRpcRef);
      if (!upstream) throw new ImpactForkError("impact_upstream_unavailable");
      runtime.proxy = await (this.deps.startProxy ?? startReadOnlyUpstreamProxy)(upstream);
      if (signal?.aborted) throw new ImpactForkError("impact_startup_cancelled");
      const call = this.deps.rpc ?? rpcCall;
      if (hexNumber(await call(runtime.proxy.url, "eth_chainId", [])) !== config.chainId) throw new ImpactForkError("impact_chain_mismatch");
      const blockHash = blockIdentity(await call(runtime.proxy.url, "eth_getBlockByNumber", [`0x${config.forkBlock.toString(16)}`, false]), config.forkBlock);
      let port = 0;
      for (let attempt = 0; attempt < 5; attempt++) {
        const candidate = await (this.deps.reservePort ?? reserveLoopbackPort)();
        if (!this.reservedPorts.has(candidate)) { port = candidate; break; }
      }
      if (!port) throw new ImpactForkError("impact_port_unavailable");
      this.reservedPorts.add(port);
      runtime.port = port;
      this.publish(runtime, { localPort: port });
      const args = anvilArguments(config, port, runtime.proxy.url);
      const child = (this.deps.launch ?? launchOwnedAnvil)(binary, args);
      child.once("error", () => {
        if (!runtime.stopping) this.publish(runtime, { status: "failed", failureCode: "impact_process_start_failed", stoppedAt: Date.now(), localRpcEndpoint: null });
      });
      if (!child.pid) throw new ImpactForkError("impact_process_start_failed");
      runtime.child = child;
      runtime.startToken = (this.deps.processToken ?? processStartToken)(child.pid);
      let outputBytes = 0;
      for (const stream of [child.stdout, child.stderr]) stream?.on("data", (chunk: Buffer) => {
        outputBytes += chunk.length;
        if (outputBytes > MAX_OUTPUT_BYTES && runtime.child?.pid) void (this.deps.terminate ?? terminateGroup)(runtime.child.pid).catch(() => undefined);
      });
      child.once("exit", () => { if (!runtime.stopping && runtime.view.status !== "stopped") {
        if (child.pid) void (this.deps.terminate ?? terminateGroup)(child.pid).catch(() => undefined);
        void runtime.proxy?.close().catch(() => undefined);
        try { this.publish(runtime, { status: "failed", failureCode: "impact_process_exited", stoppedAt: Date.now(), localRpcEndpoint: null, baselineSnapshotId: null }); }
        catch { runtime.view = { ...runtime.view, status: "failed", failureCode: "impact_process_exited", stoppedAt: Date.now(), localRpcEndpoint: null, baselineSnapshotId: null }; }
      } });
      const endpoint = `http://${HOST}:${port}`;
      const deadline = Date.now() + STARTUP_MS;
      let ready = false;
      while (Date.now() < deadline) {
        if (signal?.aborted) throw new ImpactForkError("impact_startup_cancelled");
        if (child.exitCode !== null || (runtime.view.status as string) === "failed") break;
        try {
          if ((this.deps.processToken ?? processStartToken)(child.pid) !== runtime.startToken ||
            !(this.deps.ownsPort ?? processOwnsLoopbackPort)(child.pid, port)) throw new ImpactForkError("impact_process_identity_lost");
          const version = await call(endpoint, "web3_clientVersion", []);
          const chain = hexNumber(await call(endpoint, "eth_chainId", []));
          const block = blockIdentity(await call(endpoint, "eth_getBlockByNumber", [`0x${config.forkBlock.toString(16)}`, false]), config.forkBlock);
          if (typeof version !== "string" || !/^anvil[/ ]/i.test(version) || chain !== config.chainId || block !== blockHash) throw new ImpactForkError("impact_sandbox_identity_mismatch");
          ready = true; break;
        } catch (error) {
          if (error instanceof ImpactForkError && ["impact_process_identity_lost", "impact_sandbox_identity_mismatch"].includes(error.code)) throw error;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      if (!ready) throw new ImpactForkError("impact_startup_timeout");
      if (signal?.aborted) throw new ImpactForkError("impact_startup_cancelled");
      const accounts = await call(endpoint, "eth_accounts", []);
      if (!Array.isArray(accounts) || accounts.length !== 1 || !impactAddressSchema.safeParse(accounts[0]).success) throw new ImpactForkError("impact_disposable_accounts_invalid");
      const baseline = await call(endpoint, "evm_snapshot", []);
      if (typeof baseline !== "string" || !/^0x[0-9a-f]+$/i.test(baseline)) throw new ImpactForkError("impact_snapshot_failed");
      if (child.exitCode !== null || (runtime.view.status as string) === "failed" || signal?.aborted) throw new ImpactForkError("impact_process_exited");
      runtime.snapshots = [baseline];
      this.publish(runtime, { status: "ready", forkBlockHash: blockHash, localRpcEndpoint: endpoint, anvilVersion: binary.version,
        anvilSha256: binary.sha256, processPid: child.pid, baselineSnapshotId: baseline, disposableAccounts: [accounts[0]], startedAt: Date.now() });
      runtime.timer = setTimeout(() => { void this.stopForkSession(handle); }, MAX_RUNTIME_MS);
      runtime.timer.unref();
      return copySession(runtime.view);
    } catch (error) {
      let cleanupFailed = false;
      try { await this.cleanup(runtime); } catch { cleanupFailed = true; }
      this.publish(runtime, { status: "failed", failureCode: cleanupFailed ? "impact_cleanup_failed" : error instanceof ImpactForkError ? error.code : "impact_startup_failed", stoppedAt: Date.now(), localRpcEndpoint: null });
      throw error;
    }
  }

  async assertSafeImpactExecutionEndpoint(handle: ImpactForkHandle, endpoint?: string): Promise<ImpactForkSession> {
    const runtime = this.requireHandle(handle);
    const view = runtime.view;
    if (view.status !== "ready" || !runtime.child?.pid || !runtime.startToken || !runtime.port || !view.localRpcEndpoint ||
      endpoint !== undefined && endpoint !== view.localRpcEndpoint || view.localRpcEndpoint !== `http://${HOST}:${runtime.port}` ||
      runtime.child.exitCode !== null || runtime.child.killed) throw new ImpactForkError("impact_execution_endpoint_unsafe");
    try {
      if ((this.deps.processToken ?? processStartToken)(runtime.child.pid) !== runtime.startToken ||
        !(this.deps.ownsPort ?? processOwnsLoopbackPort)(runtime.child.pid, runtime.port)) throw new Error("process identity changed");
      const call = this.deps.rpc ?? rpcCall;
      const version = await call(view.localRpcEndpoint, "web3_clientVersion", []);
      const chain = hexNumber(await call(view.localRpcEndpoint, "eth_chainId", []));
      const block = blockIdentity(await call(view.localRpcEndpoint, "eth_getBlockByNumber", [`0x${view.resolvedForkBlock.toString(16)}`, false]), view.resolvedForkBlock);
      if (typeof version !== "string" || !/^anvil[/ ]/i.test(version) || chain !== view.chainId || block !== view.forkBlockHash) throw new Error("RPC identity changed");
      return copySession(view);
    } catch {
      let cleanupFailed = false;
      try { await this.cleanup(runtime); } catch { cleanupFailed = true; }
      this.publish(runtime, { status: "failed", failureCode: cleanupFailed ? "impact_cleanup_failed" : "impact_execution_endpoint_unsafe", stoppedAt: Date.now(), localRpcEndpoint: null, baselineSnapshotId: null });
      throw new ImpactForkError("impact_execution_endpoint_unsafe");
    }
  }

  private async local(handle: ImpactForkHandle, method: string, params: unknown[]): Promise<unknown> {
    assertLocalImpactMethod(method);
    const session = await this.assertSafeImpactExecutionEndpoint(handle);
    return (this.deps.rpc ?? rpcCall)(session.localRpcEndpoint!, method, params);
  }

  async takeSnapshot(handle: ImpactForkHandle): Promise<string> {
    try {
      const id = await this.local(handle, "evm_snapshot", []);
      if (typeof id !== "string" || !/^0x[0-9a-f]+$/i.test(id)) throw new ImpactForkError("impact_snapshot_failed");
      this.requireHandle(handle).snapshots.push(id);
      return id;
    } catch (error) { if (this.getSession(handle.id)?.status === "ready") await this.failLocalOperation(handle, "impact_snapshot_failed"); throw error; }
  }

  async revertToSnapshot(handle: ImpactForkHandle, snapshotId: string): Promise<void> {
    const runtime = this.requireHandle(handle);
    const index = runtime.snapshots.indexOf(snapshotId);
    if (index < 0) throw new ImpactForkError("impact_snapshot_unknown");
    try {
      if (await this.local(handle, "evm_revert", [snapshotId]) !== true) throw new ImpactForkError("impact_revert_failed");
    } catch (error) { if (this.getSession(handle.id)?.status === "ready") await this.failLocalOperation(handle, "impact_revert_failed"); throw error; }
    runtime.snapshots.splice(index);
    if (snapshotId === runtime.view.baselineSnapshotId) this.publish(runtime, { baselineSnapshotId: null });
  }

  async resetForkSession(handle: ImpactForkHandle): Promise<string> {
    const runtime = this.requireHandle(handle);
    const baseline = runtime.view.baselineSnapshotId;
    if (!baseline) throw new ImpactForkError("impact_baseline_unavailable");
    await this.revertToSnapshot(handle, baseline);
    const replacement = await this.takeSnapshot(handle);
    this.publish(runtime, { baselineSnapshotId: replacement });
    return replacement;
  }

  async impersonate(handle: ImpactForkHandle, address: string): Promise<void> {
    impactAddressSchema.parse(address);
    if (await this.local(handle, "anvil_impersonateAccount", [address]) !== true) throw new ImpactForkError("impact_impersonation_failed");
  }

  async stopImpersonating(handle: ImpactForkHandle, address: string): Promise<void> {
    impactAddressSchema.parse(address);
    if (await this.local(handle, "anvil_stopImpersonatingAccount", [address]) !== true) throw new ImpactForkError("impact_impersonation_failed");
  }

  private async failLocalOperation(handle: ImpactForkHandle, code: string): Promise<void> {
    const runtime = this.requireHandle(handle);
    let cleanupFailed = false;
    try { await this.cleanup(runtime); } catch { cleanupFailed = true; }
    this.publish(runtime, { status: "failed", failureCode: cleanupFailed ? "impact_cleanup_failed" : code,
      stoppedAt: Date.now(), localRpcEndpoint: null, baselineSnapshotId: null });
  }

  private async cleanup(runtime: Runtime): Promise<void> {
    runtime.stopping = true;
    if (runtime.timer) clearTimeout(runtime.timer);
    let failed = false;
    if (runtime.child?.pid) try { await (this.deps.terminate ?? terminateGroup)(runtime.child.pid); } catch { failed = true; }
    try { await runtime.proxy?.close(); } catch { failed = true; }
    if (runtime.port && !failed) this.reservedPorts.delete(runtime.port);
    if (failed) throw new ImpactForkError("impact_cleanup_failed");
  }

  async stopForkSession(handle: ImpactForkHandle): Promise<ImpactForkSession> {
    const runtime = this.requireHandle(handle);
    if (runtime.view.status === "stopped") return copySession(runtime.view);
    if (runtime.view.status !== "ready" && runtime.view.status !== "failed") throw new ImpactForkError("impact_transition_invalid");
    this.publish(runtime, { status: "stopping" });
    try { await this.cleanup(runtime); }
    catch { this.publish(runtime, { status: "failed", failureCode: "impact_cleanup_failed", stoppedAt: Date.now(), localRpcEndpoint: null }); throw new ImpactForkError("impact_cleanup_failed"); }
    this.publish(runtime, { status: "stopped", stoppedAt: Date.now(), localRpcEndpoint: null, baselineSnapshotId: null });
    return copySession(runtime.view);
  }

  async shutdown(): Promise<void> {
    for (const runtime of this.sessions.values()) {
      if (runtime.view.status === "ready" || runtime.view.status === "failed") await this.stopForkSession(runtime.handle);
    }
  }
}
