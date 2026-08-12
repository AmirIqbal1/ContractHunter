import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import type { Framework } from "./domain";

export type GitHubRepository = { url: string; name: string };

export function validateGitHubUrl(input: string): GitHubRepository {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error("Enter a valid GitHub HTTPS repository URL.");
  }
  if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== "github.com" || parsed.port || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Only public-style https://github.com/owner/repository URLs are supported.");
  }
  const match = parsed.pathname.match(/^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
  if (!match || match[1] === "." || match[1] === ".." || match[2] === "." || match[2] === "..") {
    throw new Error("The URL must identify one GitHub owner and repository.");
  }
  const [, owner, repository] = match;
  return { url: `https://github.com/${owner}/${repository}.git`, name: repository };
}

export function validateGitRef(ref: string | undefined): string | undefined {
  if (!ref) return undefined;
  if (ref.length > 200 || ref.startsWith("-") || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(ref) || ref.includes("..") || ref.includes("@{") || ref.endsWith(".") || ref.endsWith("/") || ref.includes("//")) {
    throw new Error("The requested branch, tag, or commit is not valid.");
  }
  return ref;
}

export function safeScanDirectory(repositoryRoot: string, scanId: string): string {
  if (!/^[0-9a-f-]{36}$/i.test(scanId)) throw new Error("Invalid scan identifier.");
  const root = path.resolve(repositoryRoot);
  const target = path.resolve(root, scanId);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error("Unsafe repository path.");
  return target;
}

function git(args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("git", args, {
      timeout: timeoutMs,
      maxBuffer: 8_000,
      windowsHide: true,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
    }, (error, stdout, stderr) => {
      if (error?.killed) reject(new Error("Git operation timed out."));
      else if (error) reject(new Error(`Git operation failed: ${stderr.trim().slice(-500) || error.message}`));
      else resolve(stdout.trim());
    });
  });
}

export async function cloneRepository(options: { url: string; requestedRef?: string; repositoryRoot: string; scanId: string; timeoutMs: number }): Promise<{ path: string; commit: string }> {
  const repository = validateGitHubUrl(options.url);
  const requestedRef = validateGitRef(options.requestedRef);
  const target = safeScanDirectory(options.repositoryRoot, options.scanId);
  await mkdir(options.repositoryRoot, { recursive: true });
  const cloneArgs = ["clone", "--no-checkout", "--filter=blob:none", "--", repository.url, target];
  await git(cloneArgs, options.timeoutMs);
  await git(["-C", target, "checkout", "--detach", requestedRef ?? "HEAD"], options.timeoutMs);
  const commit = await git(["-C", target, "rev-parse", "HEAD"], options.timeoutMs);
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error("Git returned an invalid commit identifier.");
  return { path: target, commit };
}

export function detectFramework(repositoryPath: string): Framework {
  if (existsSync(path.join(repositoryPath, "foundry.toml"))) return "foundry";
  const hardhatFiles = ["hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs"];
  if (hardhatFiles.some((file) => existsSync(path.join(repositoryPath, file)))) return "hardhat";
  return "unknown";
}
