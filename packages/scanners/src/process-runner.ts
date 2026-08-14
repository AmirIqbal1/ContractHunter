import { spawn } from "node:child_process";

export type ProcessRequest = {
  command: string;
  args: string[];
  cwd?: string;
  timeoutMs: number;
  maxOutputBytes: number;
  env?: NodeJS.ProcessEnv;
};

export type ProcessResult = { stdout: string; stderr: string; exitCode: number };
export type ObservedProcessResult = ProcessResult & {
  durationMs: number;
  timedOut: boolean;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
};

export class ProcessTimeoutError extends Error {
  constructor() { super("Process timed out."); this.name = "ProcessTimeoutError"; }
}

export class ProcessOutputLimitError extends Error {
  constructor() { super("Process output exceeded the configured limit."); this.name = "ProcessOutputLimitError"; }
}

export type ProcessRunner = (request: ProcessRequest) => Promise<ProcessResult>;
export type ObservedProcessRunner = (request: ProcessRequest) => Promise<ObservedProcessResult>;

export const runObservedProcess: ObservedProcessRunner = (request) => new Promise((resolve, reject) => {
  const startedAt = Date.now();
  const child = spawn(request.command, request.args, {
    cwd: request.cwd,
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: request.env,
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let capturedBytes = 0;
  let stdoutTruncated = false;
  let stderrTruncated = false;
  let timedOut = false;
  let settled = false;

  const capture = (target: Buffer[], chunk: Buffer, stream: "stdout" | "stderr") => {
    const remaining = Math.max(0, request.maxOutputBytes - capturedBytes);
    if (remaining > 0) {
      const bounded = chunk.subarray(0, remaining);
      target.push(bounded);
      capturedBytes += bounded.length;
    }
    if (chunk.length > remaining) {
      if (stream === "stdout") stdoutTruncated = true;
      else stderrTruncated = true;
    }
  };
  const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, request.timeoutMs);
  child.stdout.on("data", (chunk: Buffer) => capture(stdout, chunk, "stdout"));
  child.stderr.on("data", (chunk: Buffer) => capture(stderr, chunk, "stderr"));
  child.on("error", (error) => {
    clearTimeout(timer);
    if (settled) return;
    settled = true;
    reject(error);
  });
  child.on("close", (code) => {
    clearTimeout(timer);
    if (settled) return;
    settled = true;
    resolve({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), exitCode: code ?? -1, durationMs: Date.now() - startedAt, timedOut, stdoutTruncated, stderrTruncated });
  });
});

export const runBoundedProcess: ProcessRunner = (request) => new Promise((resolve, reject) => {
  const child = spawn(request.command, request.args, {
    cwd: request.cwd,
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: request.env,
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let settled = false;
  let timedOut = false;
  let oversized = false;

  const finishWithError = (error: Error) => {
    if (settled) return;
    settled = true;
    reject(error);
  };
  const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, request.timeoutMs);
  const capture = (target: Buffer[], chunk: Buffer, stream: "stdout" | "stderr") => {
    if (stream === "stdout") stdoutBytes += chunk.length;
    else stderrBytes += chunk.length;
    if (stdoutBytes + stderrBytes > request.maxOutputBytes) {
      oversized = true;
      child.kill("SIGKILL");
      return;
    }
    target.push(chunk);
  };

  child.stdout.on("data", (chunk: Buffer) => capture(stdout, chunk, "stdout"));
  child.stderr.on("data", (chunk: Buffer) => capture(stderr, chunk, "stderr"));
  child.on("error", (error) => { clearTimeout(timer); finishWithError(error); });
  child.on("close", (code) => {
    clearTimeout(timer);
    if (settled) return;
    if (timedOut) return finishWithError(new ProcessTimeoutError());
    if (oversized) return finishWithError(new ProcessOutputLimitError());
    settled = true;
    resolve({ stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), exitCode: code ?? -1 });
  });
});
