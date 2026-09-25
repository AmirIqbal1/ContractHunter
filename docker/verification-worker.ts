import { chmod, lstat, readFile, realpath, unlink } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import net from "node:net";
import path from "node:path";
import { resolveTrustedVerificationCompiler, TrustedVerificationCompilerError } from "../packages/scanners/src/compiler-manager";
import { runObservedProcess } from "../packages/scanners/src/process-runner";
import { validateVerificationWorkspaceIntegrity, VerificationWorkspaceIntegrityError } from "../packages/scanners/src/verification-workspace-integrity";
import { validateExecutableInvariantWorkspaceIntegrity, ExecutableInvariantWorkspaceIntegrityError } from "../packages/scanners/src/executable-invariant-workspace-integrity";
import { parseInvariantForgeJson } from "../packages/scanners/src/executable-invariant-result";
import { encodeWorkerFrame, workerRequestSchema, WorkerFrameDecoder, WORKER_REQUEST_MAX_BYTES, WORKER_RESPONSE_MAX_BYTES, WORKER_SOCKET_PATH, type VerificationWorkerRequest, type ExecutableInvariantWorkerRequest } from "../packages/scanners/src/verification-worker-protocol";

const WORKSPACE_ROOT = "/verification";
const TOOL_HOME = "/data/tool-home";
const forbiddenEnvironment = /(?:^|_)(?:OPENAI|GITHUB|GH_TOKEN|RPC_URL|ETH_RPC_URL|PRIVATE_KEY|MNEMONIC|PROXY|ETHERSCAN|NPM_TOKEN|AWS_|AZURE_|GOOGLE_)/i;
const limits = { maxVirtualMemoryBytes: 2_147_483_648, maxProcesses: 64, maxOpenFiles: 256, maxFileSizeBytes: 67_108_864 } as const;
class WorkerIsolationError extends Error {}

export async function isolationPreflight(): Promise<void> {
  try {
  if (process.platform !== "linux" || process.getuid?.() !== 10002 || process.getgid?.() !== 10001) throw new WorkerIsolationError("worker identity is unavailable");
  if (Object.keys(process.env).some((key) => forbiddenEnvironment.test(key))) throw new WorkerIsolationError("worker inherited a secret or network environment key");
  const interfaces = networkInterfaces();
  if (Object.keys(interfaces).length !== 1 || !interfaces.lo?.length || interfaces.lo.some((item) => !item.internal)) throw new WorkerIsolationError("worker has a non-loopback interface");
  const route = await readFile("/proc/net/route", "utf8");
  if (route.split("\n").slice(1).some((line) => { const fields = line.trim().split(/\s+/); return fields[1] === "00000000" && fields[0] !== "lo"; })) throw new WorkerIsolationError("worker has a default IPv4 route");
  const route6 = await readFile("/proc/net/ipv6_route", "utf8").catch(() => "");
  if (route6.split("\n").some((line) => { const fields = line.trim().split(/\s+/); return fields[0] === "0".repeat(32) && fields[1] === "00" && fields.at(-1) !== "lo"; })) throw new WorkerIsolationError("worker has a default IPv6 route");
  const status = await readFile("/proc/self/status", "utf8");
  for (const [field, expected] of [["CapEff", "0000000000000000"], ["CapBnd", "0000000000000000"], ["NoNewPrivs", "1"], ["Seccomp", "2"]] as const) {
    if (!new RegExp(`^${field}:\\s*${expected}\\s*$`, "m").test(status)) throw new WorkerIsolationError(`worker ${field} check failed`);
  }
  const apparmor = (await readFile("/proc/self/attr/current", "utf8")).trim();
  if (!apparmor.endsWith("(enforce)") || apparmor.startsWith("unconfined")) throw new WorkerIsolationError("worker AppArmor is not enforcing");
  const pids = (await readFile("/sys/fs/cgroup/pids.max", "utf8")).trim();
  if (pids !== "64") throw new WorkerIsolationError("worker PID limit is not 64");
  for (const absent of ["/var/run/docker.sock", "/run/docker.sock", "/data/contracthunter.db", "/data/repositories"]) {
    try { await lstat(absent); throw new WorkerIsolationError(`worker can access forbidden path ${absent}`); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  if (await realpath(WORKSPACE_ROOT) !== WORKSPACE_ROOT || await realpath(TOOL_HOME) !== TOOL_HOME) throw new WorkerIsolationError("worker volume root is unsafe");
  } catch (error) { if (error instanceof WorkerIsolationError) throw error; throw new WorkerIsolationError("worker isolation preflight is unavailable"); }
}

function counts(output: string): { testCount: number; passedCount: number; failedCount: number } | null {
  const match = [...output.matchAll(/(\d+) tests? passed,\s*(\d+) failed|(?:(\d+) passed;\s*(\d+) failed;)/gi)].at(-1);
  if (!match) return null;
  const passedCount = Number(match[1] ?? match[3]); const failedCount = Number(match[2] ?? match[4]);
  return { testCount: passedCount + failedCount, passedCount, failedCount };
}

export async function executeVerification(request: VerificationWorkerRequest) {
  await isolationPreflight();
  const workspace = path.join(WORKSPACE_ROOT, request.workspaceId);
  const directory = await lstat(workspace);
  if (!directory.isDirectory() || directory.isSymbolicLink() || await realpath(workspace) !== workspace) throw new Error("invalid_workspace");
  const manifest = await validateVerificationWorkspaceIntegrity(workspace);
  if (manifest.verificationRunId !== request.verificationRunId || manifest.scanId !== request.scanId || manifest.hypothesisId !== request.hypothesisId || manifest.resolvedCommit !== request.resolvedCommit || manifest.compilerVersion !== request.compilerVersion) throw new Error("manifest_mismatch");
  const compiler = await resolveTrustedVerificationCompiler({ toolHomeDir: TOOL_HOME, version: request.compilerVersion });
  const cpuSeconds = Math.min(300, Math.ceil(request.timeoutMs / 1_000) + 1);
  const environment: NodeJS.ProcessEnv = { NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/contracthunter", TMPDIR: "/tmp", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", NO_COLOR: "1", FOUNDRY_PROFILE: "default", FOUNDRY_OFFLINE: "true", FOUNDRY_AUTO_DETECT_SOLC: "false", FOUNDRY_SOLC: compiler.executablePath, FOUNDRY_FFI: "false", RAYON_NUM_THREADS: "1", TOKIO_WORKER_THREADS: "1" };
  const observed = await runObservedProcess({ command: "/usr/bin/prlimit", args: [`--cpu=${cpuSeconds}:${cpuSeconds}`, `--as=${limits.maxVirtualMemoryBytes}:${limits.maxVirtualMemoryBytes}`, `--nproc=${limits.maxProcesses}:${limits.maxProcesses}`, `--nofile=${limits.maxOpenFiles}:${limits.maxOpenFiles}`, `--fsize=${limits.maxFileSizeBytes}:${limits.maxFileSizeBytes}`, "--", "/usr/local/bin/forge", "test", "--color", "never", ...(request.matchTest ? ["--match-test", request.matchTest] : [])], cwd: workspace, timeoutMs: request.timeoutMs, maxOutputBytes: request.maxOutputBytes, env: environment, killProcessTree: true });
  const count = counts(`${observed.stdout}\n${observed.stderr}`);
  return { status: observed.timedOut || observed.exitCode !== 0 ? "failed" : "completed", exitCode: observed.exitCode, durationMs: observed.durationMs, timedOut: observed.timedOut,
    testCount: count?.testCount ?? null, passedCount: count?.passedCount ?? null, failedCount: count?.failedCount ?? null,
    stdoutSummary: observed.stdout, stderrSummary: observed.stderr, stdoutTruncated: observed.stdoutTruncated, stderrTruncated: observed.stderrTruncated, outputTruncated: observed.stdoutTruncated || observed.stderrTruncated,
    errorCode: observed.timedOut ? "verification_worker_timeout" : observed.exitCode !== 0 ? "forge_failed" : null,
    errorMessage: observed.timedOut ? "Forge exceeded its wall-clock limit." : observed.exitCode !== 0 ? "Forge exited unsuccessfully." : null,
    compilerIdentity: { version: compiler.version, executablePath: compiler.executablePath },
    isolation: { providerId: "docker-verification-worker-v1", isolationVersion: "1", networkAccess: "disabled", networkIsolated: true, processIsolated: true, workerUid: 10002, resourceLimitsApplied: { maxCpuTimeSeconds: cpuSeconds, ...limits }, wallClockTimeoutMs: request.timeoutMs, maxOutputBytes: request.maxOutputBytes, writableProjectPath: workspace } } as const;
}

export async function executeInvariant(request: ExecutableInvariantWorkerRequest) {
  await isolationPreflight();
  const workspace = path.join(WORKSPACE_ROOT, request.workspaceId);
  const directory = await lstat(workspace);
  if (!directory.isDirectory() || directory.isSymbolicLink() || await realpath(workspace) !== workspace) throw new Error("invariant_workspace_invalid");
  const manifest = await validateExecutableInvariantWorkspaceIntegrity(workspace);
  if (manifest.workspaceId !== request.runId || manifest.scanId !== request.scanId || manifest.hypothesisId !== request.hypothesisId || manifest.resolvedCommit !== request.resolvedCommit || manifest.compilerVersion !== request.compilerVersion || manifest.planHash !== request.planHash || manifest.mode !== request.mode) throw new Error("invariant_manifest_mismatch");
  const compiler = await resolveTrustedVerificationCompiler({ toolHomeDir: TOOL_HOME, version: request.compilerVersion });
  const cpuSeconds = Math.min(210, Math.ceil(request.timeoutMs / 1_000) + 1);
  const environment: NodeJS.ProcessEnv = { NODE_ENV: "production", PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/contracthunter", TMPDIR: "/tmp", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", NO_COLOR: "1", FOUNDRY_PROFILE: "default", FOUNDRY_OFFLINE: "true", FOUNDRY_AUTO_DETECT_SOLC: "false", FOUNDRY_SOLC: compiler.executablePath, FOUNDRY_FFI: "false", RAYON_NUM_THREADS: "1", TOKIO_WORKER_THREADS: "1" };
  const observed = await runObservedProcess({ command: "/usr/bin/prlimit", args: [`--cpu=${cpuSeconds}:${cpuSeconds}`, `--as=${limits.maxVirtualMemoryBytes}:${limits.maxVirtualMemoryBytes}`, `--nproc=${limits.maxProcesses}:${limits.maxProcesses}`, `--nofile=${limits.maxOpenFiles}:${limits.maxOpenFiles}`, `--fsize=${limits.maxFileSizeBytes}:${limits.maxFileSizeBytes}`, "--", "/usr/local/bin/forge", "test", "--json"], cwd: workspace, timeoutMs: request.timeoutMs, maxOutputBytes: request.maxOutputBytes, env: environment, killProcessTree: true });
  const parsed = observed.timedOut || observed.stdoutTruncated || observed.stderrTruncated ? null : parseInvariantForgeJson(observed.stdout, manifest.plan);
  const consistent = parsed && ((parsed.failedCount === 0 && observed.exitCode === 0) || (parsed.failedCount > 0 && observed.exitCode !== 0));
  const errorCode = observed.timedOut ? "invariant_execution_timeout" : observed.stdoutTruncated || observed.stderrTruncated ? "invariant_result_unparseable" : !parsed ? observed.exitCode !== 0 ? "invariant_forge_failed" : "invariant_result_unparseable" : !consistent ? "invariant_result_unparseable" : null;
  return { status: errorCode ? "failed" : "completed", exitCode: observed.exitCode, durationMs: observed.durationMs, timedOut: observed.timedOut,
    testCount: parsed?.testCount ?? null, passedCount: parsed?.passedCount ?? null, failedCount: parsed?.failedCount ?? null, runsExecuted: parsed?.runsExecuted ?? null, tests: parsed?.tests ?? [], mode: manifest.mode, planHash: manifest.planHash,
    stdoutSummary: parsed ? `Forge JSON reported ${parsed.passedCount} passed and ${parsed.failedCount} failed generated properties.` : "Forge output was not a complete generated-test result.", stderrSummary: observed.stderr.slice(0, 4096), stdoutTruncated: observed.stdoutTruncated, stderrTruncated: observed.stderrTruncated || observed.stderr.length > 4096, outputTruncated: observed.stdoutTruncated || observed.stderrTruncated,
    errorCode, errorMessage: errorCode ? "Invariant execution did not produce trustworthy complete test facts." : null,
    compilerIdentity: { version: compiler.version, executablePath: compiler.executablePath },
    isolation: { providerId: "docker-verification-worker-v1", isolationVersion: "1", networkAccess: "disabled", networkIsolated: true, processIsolated: true, workerUid: 10002, resourceLimitsApplied: { maxCpuTimeSeconds: cpuSeconds, ...limits }, wallClockTimeoutMs: request.timeoutMs, maxOutputBytes: request.maxOutputBytes, writableProjectPath: workspace } } as const;
}

async function main(): Promise<void> {
  await isolationPreflight();
  const socketDirectory = path.dirname(WORKER_SOCKET_PATH);
  const info = await lstat(socketDirectory);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(socketDirectory) !== socketDirectory || (info.mode & 0o007) !== 0 || info.gid !== 10001) throw new Error("worker IPC directory is unsafe");
  try {
    const old = await lstat(WORKER_SOCKET_PATH);
    if (!old.isSocket() || old.uid !== 10002) throw new Error("unsafe stale worker socket");
    await unlink(WORKER_SOCKET_PATH);
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  let busy = false;
  const server = net.createServer((socket) => {
    const decoder = new WorkerFrameDecoder(WORKER_REQUEST_MAX_BYTES);
    const timer = setTimeout(() => socket.destroy(), 5_000);
    socket.on("data", async (chunk) => {
      let acquired = false; let invariantJob = false;
      try {
        const raw = decoder.push(chunk);
        if (raw === undefined) return;
        clearTimeout(timer);
        socket.removeAllListeners("data");
        if (busy) { socket.end(encodeWorkerFrame({ errorCode: "verification_worker_unavailable", errorMessage: "Verification worker is busy." }, WORKER_RESPONSE_MAX_BYTES)); return; }
        busy = true; acquired = true;
        const request = workerRequestSchema.parse(raw);
        invariantJob = request.command === "execute-invariant";
        const result = request.command === "verify" ? await executeVerification(request) : await executeInvariant(request);
        socket.end(encodeWorkerFrame({ result }, WORKER_RESPONSE_MAX_BYTES));
      } catch (error) {
        const reason = error instanceof Error ? error.message : "verification_worker_protocol_error";
        const code = error instanceof WorkerIsolationError ? invariantJob ? "invariant_worker_isolation_unavailable" : "verification_worker_isolation_unavailable" : error instanceof TrustedVerificationCompilerError ? "trusted_compiler_unavailable" : error instanceof VerificationWorkspaceIntegrityError ? "invalid_manifest" : error instanceof ExecutableInvariantWorkspaceIntegrityError ? "invariant_workspace_invalid" : ["invalid_workspace", "manifest_mismatch", "invariant_workspace_invalid", "invariant_manifest_mismatch"].includes(reason) ? reason : "verification_worker_protocol_error";
        socket.end(encodeWorkerFrame({ errorCode: code, errorMessage: "Verification worker refused the request." }, WORKER_RESPONSE_MAX_BYTES));
      } finally { if (acquired) busy = false; }
    });
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(WORKER_SOCKET_PATH, resolve); });
  await chmod(WORKER_SOCKET_PATH, 0o660);
  process.stdout.write("verification-worker ready\n");
}

if (process.argv[1]?.endsWith("verification-worker.cjs")) main().catch((error) => { process.stderr.write(`verification-worker startup failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; });
