import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "../../..");
type ComposeVolume = { source: string; target: string; read_only?: boolean; volume?: { subpath?: string } };
type ComposeService = { build?: { target?: string }; network_mode?: string; networks?: unknown; ports?: unknown; secrets?: unknown; user?: string; environment?: Record<string, string>; volumes?: ComposeVolume[]; read_only?: boolean; privileged?: boolean; restart?: string; pids_limit?: number; cpus?: number; cap_drop?: string[]; security_opt?: string[]; depends_on?: Record<string, { condition: string }> };
function services(): Record<string, ComposeService> {
  const configuration = JSON.parse(execFileSync("docker", ["compose", "config", "--format", "json"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })) as { services: Record<string, ComposeService> };
  return configuration.services;
}

describe("production verification worker boundary", () => {
  it("uses a networkless, non-root, capability-free worker with default Docker confinement", async () => {
    const worker = services()["verification-worker"];
    expect(worker.network_mode).toBe("none");
    expect(worker.user).toBe("10002:10001");
    expect(worker.read_only).toBe(true);
    expect(worker.pids_limit).toBe(64);
    expect(worker.cpus).toBe(1);
    expect(worker.cap_drop).toEqual(["ALL"]);
    expect(worker.security_opt).toEqual(["no-new-privileges:true"]);
    expect(worker.ports).toBeUndefined();
    expect(worker.networks).toBeUndefined();
    expect(worker.secrets).toBeUndefined();
    expect(worker.privileged).not.toBe(true);
    expect(worker.volumes?.map((volume) => volume.target)).toEqual(expect.arrayContaining(["/data/tool-home", "/verification", "/run/contracthunter-verification"]));
    expect(worker.volumes?.find((volume) => volume.source === "contracthunter-data")).toMatchObject({ target: "/data/tool-home", read_only: true, volume: { subpath: "tool-home" } });
    expect(worker.volumes?.filter((volume) => volume.source === "contracthunter-data")).toHaveLength(1);
    expect(worker.volumes?.some((volume) => /docker\.sock|contracthunter\.db|repositories/.test(volume.target))).toBe(false);
    expect(Object.keys(worker.environment ?? {})).toEqual(["NODE_ENV"]);
  });

  it("completes a constrained data initializer before the worker starts", () => {
    const configured = services();
    const initializer = configured["contracthunter-data-init"];
    expect(initializer.build?.target).toBe("data-initializer");
    expect(initializer.user).toBe("10001:10001");
    expect(initializer.network_mode).toBe("none");
    expect(initializer.ports).toBeUndefined();
    expect(initializer.networks).toBeUndefined();
    expect(initializer.secrets).toBeUndefined();
    expect(initializer.environment).toBeUndefined();
    expect(initializer.privileged).not.toBe(true);
    expect(initializer.cap_drop).toEqual(["ALL"]);
    expect(initializer.security_opt).toContain("no-new-privileges:true");
    expect(initializer.read_only).toBe(true);
    expect(initializer.restart).toBe("no");
    expect(initializer.volumes).toEqual([expect.objectContaining({ source: "contracthunter-data", target: "/data" })]);
    expect(initializer.volumes?.[0]?.read_only).not.toBe(true);
    expect(initializer.volumes?.some((volume) => /docker\.sock/.test(volume.target))).toBe(false);
    expect(configured["verification-worker"].depends_on?.["contracthunter-data-init"]?.condition).toBe("service_completed_successfully");
    expect(configured.contracthunter.depends_on?.["verification-worker"]?.condition).toBe("service_started");
  });

  it("ships Forge only in the worker runtime and excludes Bubblewrap", async () => {
    const dockerfile = await readFile(path.join(root, "Dockerfile"), "utf8");
    const worker = dockerfile.split("FROM node:22-bookworm-slim AS verification-worker-runtime")[1].split("FROM node:22-bookworm-slim AS runner")[0];
    const web = dockerfile.split("FROM node:22-bookworm-slim AS runner")[1];
    expect(worker).toContain("COPY --from=foundry /usr/local/bin/forge");
    expect(worker).toContain("util-linux");
    expect(worker).toContain("useradd --uid 10002 --gid contracthunter");
    expect(worker).not.toMatch(/bubblewrap|slither|aderyn|git |docker /i);
    expect(web).not.toMatch(/bubblewrap|prlimit --version/);
  });
  it("keeps invariant execution on the fixed worker command and bounded offline environment", async () => {
    const worker = await readFile(path.join(root, "docker/verification-worker.ts"), "utf8");
    const invariant = worker.split("export async function executeInvariant(")[1].split("async function main()")[0];
    expect(invariant).toContain("await isolationPreflight()");
    expect(invariant).toContain("validateExecutableInvariantWorkspaceIntegrity(workspace)");
    expect(invariant).toContain("resolveTrustedVerificationCompiler({ toolHomeDir: TOOL_HOME");
    expect(invariant).toContain('"/usr/bin/prlimit"');
    expect(invariant).not.toContain("--nproc=");
    expect(invariant).toContain('"/usr/local/bin/forge", "test", "--json"');
    expect(invariant).toContain('FOUNDRY_OFFLINE: "true"');
    expect(invariant).toContain('FOUNDRY_AUTO_DETECT_SOLC: "false"');
    expect(invariant).toContain('FOUNDRY_FFI: "false"');
    expect(invariant).toContain('FOUNDRY_THREADS: "1"');
    expect(invariant).toContain('NO_COLOR: "1"');
    expect(invariant).not.toMatch(/OPENAI_API_KEY|GITHUB_TOKEN|PRIVATE_KEY|MNEMONIC|RPC_URL|HTTP_PROXY|HTTPS_PROXY/);
  });
  it("keeps replay on the same fixed networkless worker surface", async () => {
    const worker = await readFile(path.join(root, "docker/verification-worker.ts"), "utf8");
    const replay = worker.split("export async function executeInvariantReplay(")[1].split("async function main()")[0];
    expect(replay).toContain("await isolationPreflight()"); expect(replay).toContain("validateInvariantReplayWorkspaceIntegrity(workspace)"); expect(replay).toContain("resolveTrustedVerificationCompiler({ toolHomeDir: TOOL_HOME"); expect(replay).toContain('"/usr/local/bin/forge", "test", "--json"'); expect(replay).toContain('FOUNDRY_OFFLINE: "true"'); expect(replay).toContain('FOUNDRY_FFI: "false"'); expect(replay).toContain('FOUNDRY_THREADS: "1"'); expect(replay).not.toMatch(/OPENAI|RPC_URL|createFork|selectFork|broadcast|--ffi|--fork-url/);
  });
});
