import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readFile, realpath, rm, unlink, writeFile } from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { z } from "zod";
import { impactPoCSourceHash } from "../packages/core/src/impact-poc";
import { resolveTrustedVerificationCompiler } from "../packages/scanners/src/compiler-manager";
import { runObservedProcess } from "../packages/scanners/src/process-runner";

const CONTROL = "/run/impact-poc/control.sock";
const BRIDGE = "/run/impact-poc/fork.sock";
const WORK = "/work";
const COMPILER_VERSION = "0.8.36";
const forgePath = "/usr/local/bin/forge";
const jobSchema = z.object({ operation: z.literal("run"), executionId: z.string().uuid(), sessionId: z.string().uuid(),
  runtimeTokenSha256: z.string().regex(/^[0-9a-f]{64}$/), source: z.string().min(1).max(16_384),
  sourceSha256: z.string().regex(/^sha256:[0-9a-f]{64}$/), entryContract: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
  sender: z.string().regex(/^0x[0-9a-fA-F]{40}$/), chainId: z.number().int().positive(), forkBlock: z.number().int().nonnegative(),
  forkBlockHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
}).strict();
type Job = z.infer<typeof jobSchema>;
let active: Job | null = null;

async function preflight(): Promise<void> {
  if (process.platform !== "linux" || process.getuid?.() !== 10003 || process.getgid?.() !== 10001) throw Error("impact_worker_identity_unsafe");
  if (Object.keys(networkInterfaces()).join(",") !== "lo") throw Error("impact_worker_network_unsafe");
  for (const name of ["/proc/net/route", "/proc/net/ipv6_route"]) {
    const lines = (await readFile(name, "utf8")).trim().split("\n").slice(1);
    if (lines.some((line) => { const fields = line.trim().split(/\s+/); return fields[0] !== "lo" && fields.at(-1) !== "lo"; }))
      throw Error("impact_worker_network_unsafe");
  }
  const status = await readFile("/proc/self/status", "utf8");
  for (const [field, expected] of [["CapEff", "0000000000000000"], ["CapBnd", "0000000000000000"],
    ["NoNewPrivs", "1"], ["Seccomp", "2"]] as const)
    if (!new RegExp(`^${field}:\\s*${expected}\\s*$`, "m").test(status)) throw Error("impact_worker_isolation_unsafe");
  const appArmor = (await readFile("/proc/self/attr/current", "utf8")).trim();
  if (!appArmor.endsWith("(enforce)")) throw Error("impact_worker_isolation_unsafe");
  if ((await readFile("/sys/fs/cgroup/pids.max", "utf8")).trim() !== "48") throw Error("impact_worker_isolation_unsafe");
  for (const forbidden of ["/var/run/docker.sock", "/data/contracthunter.db", "/data/repositories", "/verification"])
    if (await lstat(forbidden).then(() => true).catch(() => false)) throw Error("impact_worker_filesystem_unsafe");
  if (Object.keys(process.env).some((name) => /^(?:IMPACT_RPC_|OPENAI_|DATABASE_|PRIVATE_KEY|ETH_PRIVATE_KEY|FOUNDRY_ETH_RPC_URL|ETH_KEYSTORE|AWS_|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)/.test(name)))
    throw Error("impact_worker_environment_unsafe");
  if (await realpath(WORK) !== WORK) throw Error("impact_worker_workspace_unsafe");
}
async function boundedBody(request: AsyncIterable<Uint8Array>, limit: number): Promise<Buffer> {
  const parts: Uint8Array[] = []; let size = 0;
  for await (const part of request) { size += part.length; if (size > limit) throw Error("impact_worker_body_oversized"); parts.push(part); }
  return Buffer.concat(parts);
}
async function bridgeRpc(body: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest({ socketPath: BRIDGE, path: "/", method: "POST", timeout: 5000,
      headers: { "content-type": "application/json", "content-length": body.length } }, async (response) => {
      try { const raw = await boundedBody(response, 256 * 1024); if (response.statusCode !== 200) throw Error("bridge rejected"); resolve(raw); }
      catch (error) { reject(error); }
    });
    outgoing.on("error", reject); outgoing.end(body);
  });
}
async function rpc(method: string, params: unknown[]): Promise<unknown> {
  const body = await bridgeRpc(Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })));
  const value = JSON.parse(body.toString("utf8")) as { result?: unknown; error?: unknown };
  if (!("result" in value) || value.error) throw Error("impact_worker_rpc_unavailable");
  return value.result;
}
async function forgeIdentity(): Promise<{ version: string; sha256: string }> {
  const info = await lstat(forgePath);
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || info.mode & 0o022 || await realpath(forgePath) !== forgePath) throw Error("impact_forge_untrusted");
  const sha256 = createHash("sha256").update(await readFile(forgePath)).digest("hex");
  const result = await runObservedProcess({ command: forgePath, args: ["--version"], timeoutMs: 3000, maxOutputBytes: 1024,
    env: { NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/impact", LANG: "C.UTF-8" } });
  if (result.exitCode !== 0 || !/^forge Version: 1\.7\.1\n/.test(result.stdout)) throw Error("impact_forge_untrusted");
  return { version: result.stdout.trim(), sha256 };
}
async function run(job: Job) {
  const deadline = Date.now() + 30_000;
  const remaining = () => {
    const duration = deadline - Date.now();
    if (duration <= 0) throw Error("impact_job_timeout");
    return duration;
  };
  await preflight();
  if (impactPoCSourceHash(job.source) !== job.sourceSha256 || !/pragma\s+solidity\s+0\.8\.36\s*;/.test(job.source)) throw Error("impact_poc_source_invalid");
  const chain = await rpc("eth_chainId", []);
  const block = await rpc("eth_getBlockByNumber", [`0x${job.forkBlock.toString(16)}`, false]) as { hash?: string };
  if (chain !== `0x${job.chainId.toString(16)}` || block?.hash?.toLowerCase() !== job.forkBlockHash.toLowerCase()) throw Error("impact_worker_fork_identity_invalid");
  const compiler = await resolveTrustedVerificationCompiler({ toolHomeDir: "/data/tool-home", version: COMPILER_VERSION });
  const forge = await forgeIdentity();
  const root = path.join(WORK, job.executionId), script = path.join(root, "script");
  const sourceFile = path.join(script, "ImpactPoC.s.sol");
  const configFile = path.join(root, "foundry.toml");
  let ownsRoot = false;
  try {
    await mkdir(root, { mode: 0o700 });
    ownsRoot = true;
    await mkdir(script, { mode: 0o700 });
    await writeFile(sourceFile, job.source, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await writeFile(configFile, `[profile.default]\nsrc = 'script'\nscript = 'script'\nout = 'out'\ncache_path = 'cache'\nlibs = []\nffi = false\nfs_permissions = []\nauto_detect_solc = false\noffline = true\noptimizer = false\n`, { mode: 0o600, flag: "wx" });
    if (impactPoCSourceHash(await readFile(sourceFile, "utf8")) !== job.sourceSha256) throw Error("impact_poc_source_changed");
    const env: NodeJS.ProcessEnv = { NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/impact", TMPDIR: "/tmp",
      LANG: "C.UTF-8", LC_ALL: "C.UTF-8", NO_COLOR: "1", FOUNDRY_OFFLINE: "true", FOUNDRY_FFI: "false",
      FOUNDRY_AUTO_DETECT_SOLC: "false", FOUNDRY_SOLC: compiler.executablePath, FOUNDRY_THREADS: "1",
      RAYON_NUM_THREADS: "1", TOKIO_WORKER_THREADS: "1" };
    const base = ["--root", root, "--config-path", configFile, "--offline", "--no-auto-detect", "--use", compiler.executablePath,
      "--threads", "1"];
    const compiled = await runObservedProcess({ command: "/usr/bin/prlimit", args: ["--cpu=12:12", "--as=1073741824:1073741824",
      "--nofile=128:128", "--fsize=16777216:16777216", "--", forgePath, "build", ...base], cwd: root,
      timeoutMs: Math.min(12_000, remaining()),
      maxOutputBytes: 8192, env, killProcessTree: true });
    if (compiled.exitCode !== 0 || compiled.timedOut || compiled.stdoutTruncated || compiled.stderrTruncated)
      return { status: "failed", compiled: false, executed: false, exitCode: compiled.exitCode,
        stdout: compiled.stdout, stderr: compiled.stderr, errorCode: compiled.timedOut ? "compile_timeout" : "compile_failed", forge };
    const executed = await runObservedProcess({ command: "/usr/bin/prlimit", args: ["--cpu=20:20", "--as=1073741824:1073741824",
      "--nofile=128:128", "--fsize=16777216:16777216", "--", forgePath, "script", `script/ImpactPoC.s.sol:${job.entryContract}`,
      "--sig", "run()", "--broadcast", "--unlocked", "--sender", job.sender, "--rpc-url", "http://127.0.0.1:18545",
      "--non-interactive", "--json", "--no-cache", "--no-proxy", ...base], cwd: root,
      timeoutMs: Math.min(20_000, remaining()),
      maxOutputBytes: 8192, env, killProcessTree: true });
    return { status: executed.exitCode === 0 && !executed.timedOut && !executed.stdoutTruncated && !executed.stderrTruncated ? "completed" : "failed",
      compiled: true, executed: true, exitCode: executed.exitCode, stdout: executed.stdout, stderr: executed.stderr,
      errorCode: executed.timedOut ? "execution_timeout" : executed.exitCode !== 0 ? "forge_failed" : null, forge };
  } finally { if (ownsRoot) await rm(root, { recursive: true, force: true }); }
}

async function start() {
  await preflight();
  const local = createServer(async (request, response) => {
    try {
      if (!active || request.method !== "POST" || request.url !== "/") throw Error("no job");
      const body = await boundedBody(request, 64 * 1024);
      const result = await bridgeRpc(body);
      response.writeHead(200, { "content-type": "application/json" }).end(result);
    } catch { response.writeHead(503).end(); }
  });
  local.maxConnections = 32; local.requestTimeout = 5000;
  await new Promise<void>((resolve, reject) => { local.once("error", reject); local.listen(18545, "127.0.0.1", resolve); });
  await unlink(CONTROL).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
  const control = createServer(async (request, response) => {
    try {
      if (request.method !== "POST" || request.url !== "/run" || active) throw Error("impact_worker_busy");
      const job = jobSchema.parse(JSON.parse((await boundedBody(request, 20 * 1024)).toString("utf8")));
      active = job;
      try {
        const result = await run(job);
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(result));
      } finally { active = null; }
    } catch (error) {
      const reason = error instanceof Error && /^(?:impact_|trusted_compiler_)[a-z_]+$/.test(error.message) ? error.message : "impact_worker_failed";
      response.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ error: reason }));
    }
  });
  control.maxConnections = 2; control.requestTimeout = 35_000;
  await new Promise<void>((resolve, reject) => { control.once("error", reject); control.listen(CONTROL, resolve); });
  await chmod(CONTROL, 0o660);
}
start().catch(() => process.exit(1));
