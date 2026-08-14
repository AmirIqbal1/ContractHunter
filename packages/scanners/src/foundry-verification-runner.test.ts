import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VERIFICATION_HARNESS_MANIFEST } from "@contracthunter/core";
import {
  CONTRACTHUNTER_FOUNDRY_CONFIG, FoundryVerificationRunner, LinuxBubblewrapIsolationProvider, runObservedProcess,
  type FoundryVerificationInput, type ObservedProcessResult, type ObservedProcessRunner, type ProcessRequest, type VerificationIsolationConfirmation, type VerificationIsolationProvider,
} from "./index";

const scanId = "11111111-1111-4111-8111-111111111111";
const hypothesisId = "22222222-2222-4222-8222-222222222222";
const resolvedCommit = "a".repeat(40);
const success: ObservedProcessResult = { stdout: "Ran 1 test suite: 2 tests passed, 0 failed, 0 skipped", stderr: "", exitCode: 0, durationMs: 9, timedOut: false, stdoutTruncated: false, stderrTruncated: false };
const confirmation: VerificationIsolationConfirmation = {
  providerId: "fake-network-namespace", isolationVersion: "fake 1.0", networkAccess: "disabled", networkIsolated: true, processIsolated: true,
  resourceLimitsApplied: { maxCpuTimeSeconds: 300, maxVirtualMemoryBytes: 2_147_483_648, maxProcesses: 64, maxOpenFiles: 256, maxFileSizeBytes: 67_108_864 },
};

class FakeIsolationProvider implements VerificationIsolationProvider {
  constructor(private readonly available = true) {}
  async confirmNetworkIsolation() { return this.available ? confirmation : null; }
  async execute(request: ProcessRequest, processRunner: ObservedProcessRunner) {
    return { ...await processRunner(request), isolation: { ...confirmation, wallClockTimeoutMs: request.timeoutMs, maxOutputBytes: request.maxOutputBytes, writableProjectPath: request.cwd ?? "" } };
  }
}

let base: string;
let verificationRoot: string;
let repositoryRoot: string;
let workspace: string;
let toolHome: string;
let temporaryDirectory: string;

beforeEach(async () => {
  base = await mkdtemp(path.join(tmpdir(), "contracthunter-foundry-runner-"));
  verificationRoot = path.join(base, "verifications"); repositoryRoot = path.join(base, "repositories");
  workspace = path.join(verificationRoot, "run-1"); toolHome = path.join(base, "tool-home"); temporaryDirectory = path.join(base, "tmp");
  await Promise.all([mkdir(workspace, { recursive: true }), mkdir(repositoryRoot, { recursive: true }), mkdir(toolHome), mkdir(temporaryDirectory)]);
  await writeManifest();
});

afterEach(async () => { vi.unstubAllEnvs(); await rm(base, { recursive: true, force: true }); });

async function writeManifest(overrides: Record<string, unknown> = {}, contents?: string) {
  const manifest = { formatVersion: 1, scanId, hypothesisId, resolvedCommit, generatedBy: "contracthunter", createdAt: new Date().toISOString(), ...overrides };
  await writeFile(path.join(workspace, VERIFICATION_HARNESS_MANIFEST), contents ?? JSON.stringify(manifest));
}

function input(overrides: Partial<FoundryVerificationInput> = {}): FoundryVerificationInput {
  return { workspacePath: workspace, scanId, hypothesisId, resolvedCommit, timeoutMs: 5_000, maxOutputBytes: 8_192, ...overrides };
}

function runner(processRunner: ObservedProcessRunner = async () => success, isolationProvider: VerificationIsolationProvider = new FakeIsolationProvider()) {
  return new FoundryVerificationRunner({ verificationRoot, repositoryRoot, toolHomeDir: toolHome, temporaryDirectory, executablePath: "/contracthunter/bin:/usr/bin:/bin", processRunner, isolationProvider });
}

describe("FoundryVerificationRunner workspace and harness policy", () => {
  it("accepts a controlled workspace with a matching generated manifest", async () => {
    expect(await runner().run(input())).toMatchObject({ status: "completed", exitCode: 0, testCount: 2, passedCount: 2, failedCount: 0, errorCode: null });
  });

  it("rejects a workspace outside the verification root and traversal resolving outside it", async () => {
    await expect(runner().run(input({ workspacePath: repositoryRoot }))).resolves.toMatchObject({ status: "refused", errorCode: "invalid_workspace" });
    await expect(runner().run(input({ workspacePath: path.join(workspace, "..", "..", "repositories") }))).resolves.toMatchObject({ status: "refused", errorCode: "invalid_workspace" });
  });

  it("rejects a symlink escape where supported", async () => {
    const outside = path.join(base, "outside"); const link = path.join(verificationRoot, "escaped"); await mkdir(outside);
    try { await symlink(outside, link, "dir"); } catch (error) { if (["EPERM", "EACCES", "ENOSYS"].includes((error as NodeJS.ErrnoException).code ?? "")) return; throw error; }
    expect(await runner().run(input({ workspacePath: link }))).toMatchObject({ status: "refused", errorCode: "invalid_workspace" });
  });

  it("rejects missing and malformed manifests", async () => {
    await rm(path.join(workspace, VERIFICATION_HARNESS_MANIFEST));
    expect(await runner().run(input())).toMatchObject({ status: "refused", errorCode: "invalid_manifest" });
    await writeManifest({}, "{not-json");
    expect(await runner().run(input())).toMatchObject({ status: "refused", errorCode: "invalid_manifest" });
  });

  it("rejects executable configuration in the harness manifest", async () => {
    await writeManifest({ command: "forge test --ffi" });
    expect(await runner().run(input())).toMatchObject({ status: "refused", errorCode: "invalid_manifest" });
  });

  it("rejects mismatched scan, hypothesis, and commit metadata", async () => {
    for (const overrides of [{ scanId: crypto.randomUUID() }, { hypothesisId: crypto.randomUUID() }, { resolvedCommit: "b".repeat(40) }]) {
      await writeManifest(overrides);
      expect(await runner().run(input())).toMatchObject({ status: "refused", errorCode: "manifest_mismatch" });
    }
  });

  it("does not trust a repository-supplied Foundry configuration", async () => {
    await writeFile(path.join(workspace, "foundry.toml"), "[rpc_endpoints]\nmainnet = '${SECRET_RPC}'\n[profile.evil]\nffi = true\n");
    const inspect: ObservedProcessRunner = async () => {
      expect(await readFile(path.join(workspace, "foundry.toml"), "utf8")).toBe(CONTRACTHUNTER_FOUNDRY_CONFIG);
      return success;
    };
    expect(await runner(inspect).run(input())).toMatchObject({ status: "completed" });
    const controlled = await readFile(path.join(workspace, "foundry.toml"), "utf8");
    expect(controlled).toContain("ffi = false"); expect(controlled).toContain("fs_permissions = []"); expect(controlled).toContain("offline = true");
    expect(controlled).not.toMatch(/rpc_endpoints|etherscan|ffi = true|profile\.evil/);
  });
});

describe("FoundryVerificationRunner execution boundary", () => {
  it("constructs fixed argv without shell or arbitrary argument injection", async () => {
    const requests: ProcessRequest[] = [];
    const capture: ObservedProcessRunner = async (request) => { requests.push(request); return success; };
    expect(await runner(capture).run(input({ matchTest: "testDepositAccounting" }))).toMatchObject({ status: "completed" });
    expect(requests).toEqual([expect.objectContaining({ command: "forge", args: ["test", "--no-color", "--match-test", "testDepositAccounting"], cwd: workspace })]);
    expect(requests[0]).not.toHaveProperty("shell");
    expect(await runner(capture).run(input({ matchTest: "testX --ffi" }))).toMatchObject({ status: "refused", errorCode: "invalid_input" });
    expect(requests).toHaveLength(1);
  });

  it("passes a minimal environment and excludes inherited secrets", async () => {
    vi.stubEnv("OPENAI_API_KEY", "secret-ai"); vi.stubEnv("ETH_RPC_URL", "https://secret-rpc"); vi.stubEnv("ETHERSCAN_API_KEY", "secret-explorer"); vi.stubEnv("PRIVATE_KEY", "secret-wallet"); vi.stubEnv("GITHUB_TOKEN", "secret-github"); vi.stubEnv("NPM_TOKEN", "secret-npm"); vi.stubEnv("HTTP_PROXY", "http://secret-proxy"); vi.stubEnv("HTTPS_PROXY", "http://secret-proxy"); vi.stubEnv("ALL_PROXY", "socks://secret-proxy"); vi.stubEnv("NO_PROXY", "secret-internal");
    const capture: ObservedProcessRunner = async (request) => {
      expect(request.env).toEqual({ NODE_ENV: "production", PATH: "/contracthunter/bin:/usr/bin:/bin", HOME: toolHome, TMPDIR: temporaryDirectory, LANG: "C.UTF-8", LC_ALL: "C.UTF-8", NO_COLOR: "1", FOUNDRY_PROFILE: "default" });
      expect(JSON.stringify(request.env)).not.toContain("secret-"); return success;
    };
    expect(await runner(capture).run(input())).toMatchObject({ status: "completed" });
  });

  it("fails closed without explicit network isolation", async () => {
    const processRunner = vi.fn<ObservedProcessRunner>(async () => success);
    expect(await runner(processRunner, new FakeIsolationProvider(false)).run(input())).toMatchObject({ status: "refused", errorCode: "network_isolation_unavailable", exitCode: null });
    expect(processRunner).not.toHaveBeenCalled();
    expect(await new FoundryVerificationRunner({ verificationRoot, repositoryRoot, toolHomeDir: toolHome, temporaryDirectory, executablePath: "/definitely/missing", processRunner }).run(input())).toMatchObject({ status: "refused", errorCode: "network_isolation_unavailable" });
  });

  it("captures non-zero exit, timeout, and truncation as structured observations", async () => {
    const failed = { ...success, exitCode: 2, stderr: "assertion failed" };
    expect(await runner(async () => failed).run(input())).toMatchObject({ status: "failed", exitCode: 2, timedOut: false, errorCode: "forge_failed" });
    const timeout = { ...success, exitCode: -1, timedOut: true, durationMs: 5_000 };
    expect(await runner(async () => timeout).run(input())).toMatchObject({ status: "failed", timedOut: true, errorCode: "execution_timeout" });
    const truncated = { ...success, stdout: "x".repeat(100), stderr: "y".repeat(100), stdoutTruncated: true, stderrTruncated: true };
    expect(await runner(async () => truncated).run(input())).toMatchObject({ status: "completed", stdoutTruncated: true, stderrTruncated: true, outputTruncated: true });
  });

  it("returns observations without vulnerability judgement or persistence authority", async () => {
    const result = await runner().run(input());
    expect(result).not.toHaveProperty("outcome"); expect(result).not.toHaveProperty("hypothesisStatus"); expect(JSON.stringify(result)).not.toContain("verified");
    expect(result.isolation).toMatchObject({ providerId: "fake-network-namespace", networkIsolated: true, processIsolated: true, writableProjectPath: workspace });
  });
});

describe("LinuxBubblewrapIsolationProvider", () => {
  const executable = (name: string) => Promise.resolve(`/usr/bin/${name}`);
  const capabilitySuccess: ObservedProcessRunner = async (request) => request.args.includes("--version")
    ? { ...success, stdout: "bubblewrap 0.11.0" }
    : { ...success, stdout: "net:[987654321]" };
  const provider = (overrides: Partial<ConstructorParameters<typeof LinuxBubblewrapIsolationProvider>[0]> = {}) => new LinuxBubblewrapIsolationProvider({
    verificationRoot, toolHomeDir: toolHome, executableSearchPath: "/usr/bin", platform: "linux", resolveExecutable: executable,
    capabilityProcessRunner: capabilitySuccess, readParentNetworkNamespace: async () => "net:[123456789]", ...overrides,
  });

  it("is unavailable off Linux and when bwrap or prlimit is missing", async () => {
    const offLinuxRunner = vi.fn(capabilitySuccess);
    expect(await provider({ platform: "darwin", capabilityProcessRunner: offLinuxRunner }).confirmNetworkIsolation()).toBeNull();
    expect(offLinuxRunner).not.toHaveBeenCalled();
    expect(await provider({ resolveExecutable: async (name) => name === "bwrap" ? null : `/usr/bin/${name}` }).confirmNetworkIsolation()).toBeNull();
    expect(await provider({ resolveExecutable: async (name) => name === "prlimit" ? null : `/usr/bin/${name}` }).confirmNetworkIsolation()).toBeNull();
  });

  it("fails closed for resource limits outside conservative bounds", async () => {
    expect(await provider({ resourceLimits: { maxProcesses: 10_000 } }).confirmNetworkIsolation()).toBeNull();
    expect(await provider({ resourceLimits: { maxVirtualMemoryBytes: 1_024 } }).confirmNetworkIsolation()).toBeNull();
  });

  it("fails closed when the namespace probe fails or does not isolate networking", async () => {
    const failedProbe: ObservedProcessRunner = async (request) => request.args.includes("--version") ? { ...success, stdout: "bubblewrap 0.11.0" } : { ...success, exitCode: 1 };
    expect(await provider({ capabilityProcessRunner: failedProbe }).confirmNetworkIsolation()).toBeNull();
    const inheritedNetwork: ObservedProcessRunner = async (request) => request.args.includes("--version") ? { ...success, stdout: "bubblewrap 0.11.0" } : { ...success, stdout: "net:[123456789]" };
    expect(await provider({ capabilityProcessRunner: inheritedNetwork }).confirmNetworkIsolation()).toBeNull();
  });

  it("probes required namespaces and limits using fixed argv", async () => {
    const requests: ProcessRequest[] = [];
    const probe: ObservedProcessRunner = async (request) => { requests.push(request); return capabilitySuccess(request); };
    expect(await provider({ capabilityProcessRunner: probe }).confirmNetworkIsolation()).toMatchObject({ providerId: "linux-bubblewrap", networkAccess: "disabled", networkIsolated: true, processIsolated: true });
    expect(requests).toHaveLength(2);
    const namespaceProbe = requests[1];
    expect(namespaceProbe.command).toBe("/usr/bin/prlimit");
    expect(namespaceProbe.args).toEqual(expect.arrayContaining(["--cpu=2:2", "--as=2147483648:2147483648", "--nproc=64:64", "--nofile=256:256", "--fsize=67108864:67108864", "/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent", "--new-session"]));
    expect(namespaceProbe).not.toHaveProperty("shell");
    expect(namespaceProbe.args.join(" ")).not.toMatch(/(?:^|\s)(?:sudo|docker|podman|bash|sh)(?:\s|$)/);
  });

  it("wraps Forge with a single writable project path, sanitised environment, and bounded limits", async () => {
    const requests: ProcessRequest[] = [];
    const execute: ObservedProcessRunner = async (request) => { requests.push(request); return success; };
    const result = await provider().execute({
      command: "forge", args: ["test", "--no-color"], cwd: workspace, timeoutMs: 5_000, maxOutputBytes: 8_192,
      env: { NODE_ENV: "production", PATH: "/host/secret", HOME: "/host/home", TMPDIR: "/host/tmp", FOUNDRY_PROFILE: "default", HTTP_PROXY: "http://secret", OPENAI_API_KEY: "secret" },
    }, execute);
    expect(result.isolation).toMatchObject({ providerId: "linux-bubblewrap", wallClockTimeoutMs: 5_000, maxOutputBytes: 8_192, writableProjectPath: workspace });
    expect(requests).toHaveLength(1);
    const wrapped = requests[0];
    expect(wrapped).toMatchObject({ command: "/usr/bin/prlimit", cwd: workspace, timeoutMs: 5_000, maxOutputBytes: 8_192, killProcessTree: true, env: { NODE_ENV: "production", PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } });
    expect(wrapped.args).toEqual(expect.arrayContaining(["--cpu=6:6", "--unshare-net", "--unshare-pid", "--clearenv", "--ro-bind", "/usr/bin/forge", "/opt/contracthunter/bin/forge", "--bind", workspace, workspace, "--chdir", workspace, "--", "/opt/contracthunter/bin/forge", "test", "--no-color"]));
    const writableBinds = wrapped.args.flatMap((argument, index) => argument === "--bind" ? [[wrapped.args[index + 1], wrapped.args[index + 2]]] : []);
    expect(writableBinds).toEqual([[workspace, workspace]]);
    expect(wrapped.args.join(" ")).not.toMatch(/secret|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|OPENAI_API_KEY|GITHUB_TOKEN|PRIVATE_KEY|MNEMONIC|RPC_URL|ETH_RPC_URL|ETHERSCAN_API_KEY|NPM_TOKEN|docker|podman|sudo/);
  });

  it("captures a bwrap execution failure without granting vulnerability status authority", async () => {
    const isolated = provider();
    const failedRunner = runner(async () => ({ ...success, exitCode: 125, stderr: "bwrap failed" }), isolated);
    const result = await failedRunner.run(input());
    expect(result).toMatchObject({ status: "failed", exitCode: 125, errorCode: "forge_failed", isolation: { providerId: "linux-bubblewrap" } });
    expect(result).not.toHaveProperty("verified"); expect(result).not.toHaveProperty("hypothesisStatus");
  });

  it("rejects arbitrary executable requests", async () => {
    await expect(provider().execute({ command: "bash", args: ["-c", "forge test"], cwd: workspace, timeoutMs: 5_000, maxOutputBytes: 8_192 }, async () => success)).rejects.toThrow();
  });
});

describe("observed process limits", () => {
  it("kills a timed-out child and records the timeout", async () => {
    const result = await runObservedProcess({ command: process.execPath, args: ["-e", "setInterval(() => {}, 1000)"], timeoutMs: 100, maxOutputBytes: 1_024, env: { NODE_ENV: "test", PATH: process.env.PATH }, killProcessTree: true });
    expect(result).toMatchObject({ timedOut: true, exitCode: -1 }); expect(result.durationMs).toBeLessThan(5_000);
  });

  it("kills descendants in the isolated process group on timeout", async () => {
    const sentinel = path.join(base, "descendant-survived");
    const descendant = "setTimeout(() => require('node:fs').writeFileSync(process.argv[1], 'survived'), 400); setInterval(() => {}, 1000)";
    const parent = `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(descendant)}, process.argv[1]], { stdio: 'ignore' }); setInterval(() => {}, 1000)`;
    const result = await runObservedProcess({ command: process.execPath, args: ["-e", parent, sentinel], timeoutMs: 100, maxOutputBytes: 1_024, env: { NODE_ENV: "test", PATH: process.env.PATH }, killProcessTree: true });
    expect(result.timedOut).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 600));
    await expect(readFile(sentinel, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("bounds stdout and stderr while recording truncation", async () => {
    const stdout = await runObservedProcess({ command: "/usr/bin/head", args: ["-c", "4096", "/dev/zero"], timeoutMs: 5_000, maxOutputBytes: 1_024, env: { NODE_ENV: "test", PATH: "/usr/bin:/bin" } });
    expect(Buffer.byteLength(stdout.stdout) + Buffer.byteLength(stdout.stderr)).toBeLessThanOrEqual(1_024);
    expect(stdout.stdoutTruncated).toBe(true); expect(stdout.timedOut).toBe(false); expect(stdout.exitCode).toBe(0);
    const stderr = await runObservedProcess({ command: "/usr/bin/ls", args: Array.from({ length: 200 }, (_, index) => `/missing-contracthunter-${index}`), timeoutMs: 5_000, maxOutputBytes: 1_024, env: { NODE_ENV: "test", PATH: "/usr/bin:/bin", LC_ALL: "C" } });
    expect(Buffer.byteLength(stderr.stdout) + Buffer.byteLength(stderr.stderr)).toBeLessThanOrEqual(1_024);
    expect(stderr.stderrTruncated).toBe(true); expect(stderr.timedOut).toBe(false); expect(stderr.exitCode).not.toBe(0);
  });
});
