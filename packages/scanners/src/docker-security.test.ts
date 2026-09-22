import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "../../..");

describe("production verification worker boundary", () => {
  it("uses a networkless, non-root, capability-free worker with default Docker confinement", async () => {
    const compose = await readFile(path.join(root, "docker-compose.yml"), "utf8");
    const worker = compose.split("  verification-worker:\n")[1].split("\nvolumes:")[0];
    expect(worker).toContain('network_mode: "none"');
    expect(worker).toContain('user: "10002:10001"');
    expect(worker).toContain("read_only: true");
    expect(worker).toContain("pids_limit: 64");
    expect(worker).toContain("- no-new-privileges:true");
    expect(worker).toContain("cap_drop:\n      - ALL");
    expect(worker).toContain("subpath: tool-home");
    expect(worker).not.toMatch(/ports:|networks:|docker\.sock|privileged:|apparmor:|seccomp:|OPENAI_API_KEY|GITHUB_TOKEN|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY/);
    expect(compose).not.toMatch(/seccomp:\.\/docker|apparmor:contracthunter|network_mode:\s*host|CAP_SYS_ADMIN/);
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
});
