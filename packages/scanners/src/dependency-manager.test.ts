import { copyFileSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { DependencyManager, dependencyInternals, type DependencyManagerOptions } from "./dependency-manager";
import { ProcessTimeoutError, type ProcessRequest, type ProcessRunner } from "./process-runner";

const commit = "a".repeat(40);

function workspace() {
  const root = mkdtempSync(path.join(tmpdir(), "contracthunter-deps-"));
  const repository = path.join(root, "repositories", "scan");
  const toolHome = path.join(root, "tool-home");
  mkdirSync(repository, { recursive: true });
  return { root, repository, toolHome };
}

function options(root: string, toolHome: string, runner: ProcessRunner, overrides: Partial<DependencyManagerOptions> = {}): DependencyManagerOptions {
  return { workspaceRoot: path.join(root, "repositories"), toolHomeDir: toolHome, timeoutMs: 300_000, maxOutputBytes: 20_971_520, maxSubmoduleDepth: 5, maxSubmodules: 100, allowNpm: true, allowGitSubmodules: true, allowedGitHosts: ["github.com"], processRunner: runner, ...overrides };
}

const ok = { stdout: "", stderr: "", exitCode: 0 };

function gitRunner(requests: ProcessRequest[], prepared = false): ProcessRunner {
  const updated = new Set<string>();
  return async (request) => {
    requests.push(request);
    if (request.args[0] === "--version") return { ...ok, stdout: "git version 2.47.0" };
    if (request.args.includes("status")) return { ...ok, stdout: `${prepared || updated.has(path.resolve(request.cwd ?? "", request.args.at(-1) ?? "")) ? " " : "-"}${commit} ${request.args.at(-1)}\n` };
    if (request.args.includes("update")) {
      const target = path.resolve(request.cwd ?? "", request.args.at(-1) ?? "");
      mkdirSync(target, { recursive: true });
      updated.add(target);
      return ok;
    }
    return ok;
  };
}

function writeModules(repository: string, entries: Array<{ name: string; modulePath: string; url: string; update?: string }>) {
  writeFileSync(path.join(repository, ".gitmodules"), entries.map((entry) => `[submodule "${entry.name}"]\n path = ${entry.modulePath}\n url = ${entry.url}\n${entry.update ? ` update = ${entry.update}\n` : ""}`).join("\n"));
}

describe("safe Git submodule preparation", () => {
  it("skips repositories without .gitmodules", async () => {
    const { root, repository, toolHome } = workspace();
    const result = await new DependencyManager(options(root, toolHome, async () => ok)).prepare(repository);
    expect(result.status).toBe("skipped");
    expect(result.metadata.gitSubmodulesDetected).toBe(0);
  });

  it("prepares one or multiple approved GitHub HTTPS submodules without --remote", async () => {
    const { root, repository, toolHome } = workspace();
    writeModules(repository, [
      { name: "openzeppelin", modulePath: "lib/openzeppelin", url: "https://github.com/OpenZeppelin/openzeppelin-contracts.git" },
      { name: "solmate", modulePath: "lib/solmate", url: "https://github.com/transmissions11/solmate.git" },
    ]);
    const requests: ProcessRequest[] = [];
    const result = await new DependencyManager(options(root, toolHome, gitRunner(requests))).prepare(repository);
    expect(result.metadata).toMatchObject({ gitSubmodulesDetected: 2, gitSubmodulesPrepared: 2 });
    const updates = requests.filter((request) => request.args.includes("update"));
    expect(updates).toHaveLength(2);
    expect(updates.every((request) => request.args.includes("--checkout") && !request.args.includes("--remote"))).toBe(true);
    expect(updates[0].env).toMatchObject({ GIT_TERMINAL_PROMPT: "0", GIT_PROTOCOL_FROM_USER: "0" });
    expect(updates[0].args).toEqual(expect.arrayContaining(["protocol.file.allow=never", "protocol.ssh.allow=never", "protocol.git.allow=never"]));
  });

  it("validates and prepares nested submodules one level at a time", async () => {
    const { root, repository, toolHome } = workspace();
    writeModules(repository, [{ name: "parent", modulePath: "lib/parent", url: "https://github.com/example/parent.git" }]);
    const requests: ProcessRequest[] = [];
    const runner: ProcessRunner = async (request) => {
      requests.push(request);
      if (request.args[0] === "--version") return { ...ok, stdout: "git version 2.47.0" };
      if (request.args.includes("status")) return { ...ok, stdout: `${requests.some((item) => item.args.includes("update") && item.cwd === request.cwd) ? " " : "-"}${commit} child\n` };
      if (request.args.includes("update")) {
        const target = path.resolve(request.cwd ?? "", request.args.at(-1) ?? "");
        mkdirSync(target, { recursive: true });
        if (request.cwd === repository) writeModules(target, [{ name: "child", modulePath: "lib/child", url: "https://github.com/example/child.git" }]);
      }
      return ok;
    };
    const result = await new DependencyManager(options(root, toolHome, runner)).prepare(repository);
    expect(result.metadata.gitSubmodulesPrepared).toBe(2);
    expect(requests.filter((request) => request.args.includes("update")).map((request) => request.cwd)).toEqual([repository, path.join(repository, "lib/parent")]);
  });

  it("reuses a submodule already checked out at its pinned commit", async () => {
    const { root, repository, toolHome } = workspace();
    writeModules(repository, [{ name: "ready", modulePath: "lib/ready", url: "https://github.com/example/ready.git" }]);
    mkdirSync(path.join(repository, "lib/ready"), { recursive: true });
    const requests: ProcessRequest[] = [];
    const result = await new DependencyManager(options(root, toolHome, gitRunner(requests, true))).prepare(repository);
    expect(result.metadata.gitSubmodulesPrepared).toBe(1);
    expect(requests.some((request) => request.args.includes("update"))).toBe(false);
  });

  it.each([
    ["../escape", "https://github.com/example/repo.git"],
    ["/absolute", "https://github.com/example/repo.git"],
    ["lib/x", "file:///tmp/repo"],
    ["lib/x", "git://github.com/example/repo.git"],
    ["lib/x", "ssh://git@github.com/example/repo.git"],
    ["lib/x", "git@github.com:example/repo.git"],
    ["lib/x", "https://user:secret@github.com/example/repo.git"],
    ["lib/x", "https://gitlab.com/example/repo.git"],
  ])("rejects unsafe submodule path %s or URL %s", async (modulePath, url) => {
    const { root, repository, toolHome } = workspace();
    writeModules(repository, [{ name: "unsafe", modulePath, url }]);
    await expect(new DependencyManager(options(root, toolHome, async () => ok)).prepare(repository)).rejects.toThrow(/unsafe path|approved HTTPS|approved HTTPS dependency host/);
  });

  it("rejects custom update commands and excessive module counts", async () => {
    const first = workspace();
    writeModules(first.repository, [{ name: "evil", modulePath: "lib/evil", url: "https://github.com/example/evil.git", update: "!touch sentinel" }]);
    await expect(new DependencyManager(options(first.root, first.toolHome, async () => ok)).prepare(first.repository)).rejects.toThrow("Custom Git submodule update");
    const second = workspace();
    writeModules(second.repository, [{ name: "a", modulePath: "lib/a", url: "https://github.com/example/a.git" }, { name: "b", modulePath: "lib/b", url: "https://github.com/example/b.git" }]);
    await expect(new DependencyManager(options(second.root, second.toolHome, gitRunner([]), { maxSubmodules: 1 })).prepare(second.repository)).rejects.toThrow("configured limit");
  });

  it("rejects excessive recursion", async () => {
    const { root, repository, toolHome } = workspace();
    writeModules(repository, [{ name: "parent", modulePath: "lib/parent", url: "https://github.com/example/parent.git" }]);
    const requests: ProcessRequest[] = [];
    const runner: ProcessRunner = async (request) => {
      requests.push(request);
      if (request.args[0] === "--version") return { ...ok, stdout: "git version" };
      if (request.args.includes("status")) return { ...ok, stdout: `${requests.some((item) => item.args.includes("update")) ? " " : "-"}${commit} x\n` };
      const target = path.resolve(request.cwd ?? "", request.args.at(-1) ?? "");
      mkdirSync(target, { recursive: true });
      writeModules(target, [{ name: "child", modulePath: "child", url: "https://github.com/example/child.git" }]);
      return ok;
    };
    await expect(new DependencyManager(options(root, toolHome, runner, { maxSubmoduleDepth: 1 })).prepare(repository)).rejects.toThrow("recursion limit");
  });

  it("reports Git unavailability, timeout, and process failure cleanly", async () => {
    for (const mode of ["missing", "timeout", "failure"] as const) {
      const { root, repository, toolHome } = workspace();
      writeModules(repository, [{ name: "dep", modulePath: "lib/dep", url: "https://github.com/example/dep.git" }]);
      const runner: ProcessRunner = async (request) => {
        if (request.args[0] === "--version") {
          if (mode === "missing") throw new Error("ENOENT");
          return { ...ok, stdout: "git version" };
        }
        if (request.args.includes("status")) return { ...ok, stdout: `-${commit} dep\n` };
        if (mode === "timeout") throw new ProcessTimeoutError();
        return { stdout: "", stderr: "credential https://user:secret@github.com failed", exitCode: 1 };
      };
      const rejection = expect(new DependencyManager(options(root, toolHome, runner)).prepare(repository)).rejects;
      if (mode === "missing") await rejection.toThrow("Git is not available");
      if (mode === "timeout") await rejection.toThrow("timed out");
      if (mode === "failure") await rejection.toThrow("https://github.com failed");
    }
  });
});

function writeNpm(repository: string, manifest: Record<string, unknown>, lockfile: "package-lock.json" | "npm-shrinkwrap.json" | null = "package-lock.json", lockPackages: Record<string, unknown> = {}) {
  writeFileSync(path.join(repository, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", ...manifest }));
  if (lockfile) writeFileSync(path.join(repository, lockfile), JSON.stringify({ name: "fixture", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "fixture", version: "1.0.0" }, ...lockPackages } }));
}

describe("safe npm dependency preparation", () => {
  it.each(["package-lock.json", "npm-shrinkwrap.json"] as const)("runs restricted npm ci for %s", async (lockfile) => {
    const { root, repository, toolHome } = workspace();
    writeNpm(repository, { dependencies: { lodash: "^4.17.21" } }, lockfile, { "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", integrity: "sha512-test" } });
    const requests: ProcessRequest[] = [];
    const runner: ProcessRunner = async (request) => { requests.push(request); return request.args[0] === "--version" ? { ...ok, stdout: "11.0.0" } : ok; };
    const result = await new DependencyManager(options(root, toolHome, runner)).prepare(repository);
    expect(result.metadata).toMatchObject({ packageManager: "npm", lockfile, npmDependenciesDetected: 1, npmDependenciesPrepared: 1 });
    const ci = requests.find((request) => request.args[0] === "ci");
    expect(ci?.args).toEqual(expect.arrayContaining(["--ignore-scripts", "--no-audit", "--no-fund", "--allow-git=root", "--registry=https://registry.npmjs.org/"]));
    expect(ci?.env).not.toHaveProperty("NPM_TOKEN");
    expect(ci?.env).not.toHaveProperty("SSH_AUTH_SOCK");
  });

  it("does not run npm without both package.json and a supported lockfile", async () => {
    const noPackage = workspace();
    writeFileSync(path.join(noPackage.repository, "package-lock.json"), "{}");
    const first = await new DependencyManager(options(noPackage.root, noPackage.toolHome, async () => { throw new Error("must not run"); })).prepare(noPackage.repository);
    expect(first.status).toBe("skipped");
    const noLock = workspace();
    writeNpm(noLock.repository, {}, null);
    const second = await new DependencyManager(options(noLock.root, noLock.toolHome, async () => { throw new Error("must not run"); })).prepare(noLock.repository);
    expect(second.metadata.warnings[0]).toContain("no supported lockfile");
  });

  it.each([
    ["local", "file:../local", "local filesystem"],
    ["directory", "../local", "local filesystem"],
    ["ssh", "git+ssh://git@github.com/example/repo.git", "SSH"],
    ["scp", "git@github.com:example/repo.git", "SSH"],
    ["host", "git+https://gitlab.com/example/repo.git", "unapproved"],
    ["tarball", "https://github.com/example/archive.tgz", "unapproved"],
  ])("rejects %s npm sources", async (_name, spec, message) => {
    const { root, repository, toolHome } = workspace();
    writeNpm(repository, { dependencies: { unsafe: spec } });
    await expect(new DependencyManager(options(root, toolHome, async () => ok)).prepare(repository)).rejects.toThrow(message);
  });

  it("rejects lockfile directory links and unapproved transitive remotes", async () => {
    const linked = workspace();
    writeNpm(linked.repository, {}, "package-lock.json", { "node_modules/local": { resolved: "../local", link: true } });
    await expect(new DependencyManager(options(linked.root, linked.toolHome, async () => ok)).prepare(linked.repository)).rejects.toThrow("directory dependency");
    const remote = workspace();
    writeNpm(remote.repository, {}, "package-lock.json", { "node_modules/transitive": { version: "1.0.0", resolved: "https://evil.example/package.tgz" } });
    await expect(new DependencyManager(options(remote.root, remote.toolHome, async () => ok)).prepare(remote.repository)).rejects.toThrow("unapproved remote");
  });

  it("does not allow project npmrc to override policy", async () => {
    const { root, repository, toolHome } = workspace();
    writeNpm(repository, {});
    writeFileSync(path.join(repository, ".npmrc"), "ignore-scripts=false\n//registry.npmjs.org/:_authToken=secret");
    await expect(new DependencyManager(options(root, toolHome, async () => ok)).prepare(repository)).rejects.toThrow("Repository .npmrc");
  });

  it("reports npm unavailable, timeout, and npm ci failure", async () => {
    for (const mode of ["missing", "timeout", "failure"] as const) {
      const { root, repository, toolHome } = workspace();
      writeNpm(repository, {});
      const runner: ProcessRunner = async (request) => {
        if (request.args[0] === "--version") {
          if (mode === "missing") throw new Error("ENOENT");
          return { ...ok, stdout: "11.0.0" };
        }
        if (mode === "timeout") throw new ProcessTimeoutError();
        return { stdout: "", stderr: "auth https://user:token@registry.npmjs.org failed", exitCode: 1 };
      };
      const rejection = expect(new DependencyManager(options(root, toolHome, runner)).prepare(repository)).rejects;
      if (mode === "missing") await rejection.toThrow("npm is not available");
      if (mode === "timeout") await rejection.toThrow("timed out");
      if (mode === "failure") await rejection.toThrow("https://registry.npmjs.org failed");
    }
  });

  it("does not execute a malicious lifecycle script in a local integration fixture", async () => {
    const { root, repository, toolHome } = workspace();
    const sentinel = path.join(repository, "sentinel-created");
    const fixture = path.resolve(import.meta.dirname, "../fixtures/malicious-package");
    copyFileSync(path.join(fixture, "package.json"), path.join(repository, "package.json"));
    copyFileSync(path.join(fixture, "package-lock.json"), path.join(repository, "package-lock.json"));
    const result = await new DependencyManager(options(root, toolHome, undefined as unknown as ProcessRunner)).prepare(repository);
    expect(result.status).toBe("ready");
    expect(existsSync(sentinel)).toBe(false);
  });
});

describe("dependency data parsers", () => {
  it("parses deterministic .gitmodules data", () => {
    expect(dependencyInternals.parseGitmodules('[submodule "a"]\npath = lib/a\nurl = https://github.com/example/a.git')).toEqual([{ name: "a", path: "lib/a", url: "https://github.com/example/a.git" }]);
  });
});
