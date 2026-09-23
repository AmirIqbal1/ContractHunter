import net from "node:net";
import path from "node:path";
import { realpath } from "node:fs/promises";
import { z } from "zod";
import type { FoundryVerificationInput, FoundryVerificationResult } from "./foundry-verification-runner";
import { encodeWorkerFrame, verificationWorkerRequestSchema, WorkerFrameDecoder, WORKER_REQUEST_MAX_BYTES, WORKER_RESPONSE_MAX_BYTES, WORKER_SOCKET_PATH } from "./verification-worker-protocol";

const limits = z.object({ maxCpuTimeSeconds: z.number().int().min(1).max(300), maxVirtualMemoryBytes: z.literal(2_147_483_648), maxProcesses: z.literal(64), maxOpenFiles: z.literal(256), maxFileSizeBytes: z.literal(67_108_864) }).strict();
const isolation = z.object({ providerId: z.literal("docker-verification-worker-v1"), isolationVersion: z.literal("1"), networkAccess: z.literal("disabled"), networkIsolated: z.literal(true), processIsolated: z.literal(true), resourceLimitsApplied: limits, wallClockTimeoutMs: z.number().int(), maxOutputBytes: z.number().int(), writableProjectPath: z.string(), workerUid: z.literal(10002) }).strict();
const resultSchema = z.object({
  status: z.enum(["completed", "failed", "refused"]), exitCode: z.number().int().nullable(), durationMs: z.number().int().nonnegative(), timedOut: z.boolean(),
  testCount: z.number().int().nonnegative().nullable(), passedCount: z.number().int().nonnegative().nullable(), failedCount: z.number().int().nonnegative().nullable(),
  stdoutSummary: z.string(), stderrSummary: z.string(), stdoutTruncated: z.boolean(), stderrTruncated: z.boolean(), outputTruncated: z.boolean(),
  errorCode: z.string().nullable(), errorMessage: z.string().nullable(), isolation: isolation.nullable(),
  compilerIdentity: z.object({ version: z.string(), executablePath: z.string() }).strict(),
}).strict();
const workerErrorCode = z.enum(["invalid_workspace", "invalid_manifest", "manifest_mismatch", "trusted_compiler_unavailable", "verification_worker_unavailable", "verification_worker_isolation_unavailable", "verification_worker_protocol_error"]);
const responseSchema = z.union([z.object({ result: resultSchema }).strict(), z.object({ errorCode: workerErrorCode, errorMessage: z.string().max(256) }).strict()]);

export function workerFailure(code: FoundryVerificationResult["errorCode"], message: string, startedAt = Date.now()): FoundryVerificationResult {
  return { status: "refused", exitCode: null, durationMs: Date.now() - startedAt, timedOut: false, testCount: null, passedCount: null, failedCount: null, stdoutSummary: "", stderrSummary: "", stdoutTruncated: false, stderrTruncated: false, outputTruncated: false, errorCode: code, errorMessage: message, isolation: null };
}

export class VerificationWorkerClient {
  constructor(private readonly verificationRoot: string, private readonly socketPath = WORKER_SOCKET_PATH) {}

  async run(input: FoundryVerificationInput): Promise<FoundryVerificationResult> {
    const startedAt = Date.now();
    let workspace: string;
    let request;
    try {
      const root = await realpath(this.verificationRoot);
      workspace = await realpath(input.workspacePath);
      if (path.dirname(workspace) !== root || path.basename(workspace) !== path.basename(input.workspacePath)) throw new Error("invalid workspace");
      request = verificationWorkerRequestSchema.parse({ command: "verify", verificationRunId: path.basename(workspace), workspaceId: path.basename(workspace), scanId: input.scanId, hypothesisId: input.hypothesisId, resolvedCommit: input.resolvedCommit, compilerVersion: input.compilerVersion, timeoutMs: input.timeoutMs, maxOutputBytes: input.maxOutputBytes, matchTest: input.matchTest });
    } catch { return workerFailure("invalid_input", "Verification request or workspace is invalid.", startedAt); }
    try {
      const response = await new Promise<unknown>((resolve, reject) => {
        const socket = net.createConnection(this.socketPath);
        const decoder = new WorkerFrameDecoder(WORKER_RESPONSE_MAX_BYTES);
        const timer = setTimeout(() => { socket.destroy(); reject(new Error("verification_worker_timeout")); }, request.timeoutMs + 20_000);
        let settled = false;
        const finish = (error?: Error, value?: unknown) => { if (settled) return; settled = true; clearTimeout(timer); socket.destroy(); if (error) reject(error); else resolve(value); };
        socket.on("connect", () => { try { socket.write(encodeWorkerFrame(request, WORKER_REQUEST_MAX_BYTES)); } catch { finish(new Error("verification_worker_protocol_error")); } });
        socket.on("data", (chunk: Buffer) => { try { const value = decoder.push(chunk); if (value !== undefined) finish(undefined, value); } catch { finish(new Error("verification_worker_protocol_error")); } });
        socket.on("error", () => finish(new Error("verification_worker_unavailable")));
        socket.on("end", () => finish(new Error("verification_worker_protocol_error")));
      });
      const parsed = responseSchema.safeParse(response);
      if (!parsed.success) return workerFailure("verification_worker_protocol_error", "Verification worker returned an invalid response.", startedAt);
      if ("errorCode" in parsed.data) return workerFailure(parsed.data.errorCode, parsed.data.errorMessage, startedAt);
      const result = parsed.data.result;
      const observed = result.isolation;
      const expectedCompilerPath = `/data/tool-home/.solc-select/artifacts/solc-${request.compilerVersion}/solc-${request.compilerVersion}`;
      if (!observed || observed.wallClockTimeoutMs !== request.timeoutMs || observed.maxOutputBytes !== request.maxOutputBytes || observed.writableProjectPath !== workspace || result.compilerIdentity.version !== request.compilerVersion || result.compilerIdentity.executablePath !== expectedCompilerPath || Buffer.byteLength(result.stdoutSummary) + Buffer.byteLength(result.stderrSummary) > request.maxOutputBytes) return workerFailure("verification_worker_protocol_error", "Verification worker isolation or compiler metadata was invalid.", startedAt);
      return result as FoundryVerificationResult;
    } catch (error) {
      const code = error instanceof Error && error.message === "verification_worker_timeout" ? "verification_worker_timeout" : error instanceof Error && error.message === "verification_worker_protocol_error" ? "verification_worker_protocol_error" : "verification_worker_unavailable";
      return workerFailure(code, "Verification worker is unavailable or did not complete the bounded request.", startedAt);
    }
  }
}
