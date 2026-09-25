import { z } from "zod";

export const WORKER_REQUEST_MAX_BYTES = 4096;
export const WORKER_RESPONSE_MAX_BYTES = 21_100_000;
export const WORKER_SOCKET_PATH = "/run/contracthunter-verification/worker.sock";
const uuid = z.string().uuid();

export const verificationWorkerRequestSchema = z.object({
  command: z.literal("verify"),
  verificationRunId: uuid,
  workspaceId: uuid,
  scanId: uuid,
  hypothesisId: uuid,
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/),
  compilerVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  timeoutMs: z.number().int().min(100).max(1_800_000),
  maxOutputBytes: z.number().int().min(1_024).max(20_971_520),
  matchTest: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/).optional(),
}).strict().refine((request) => request.workspaceId === request.verificationRunId, "Workspace must match the verification run.");

export type VerificationWorkerRequest = z.infer<typeof verificationWorkerRequestSchema>;

export function encodeWorkerFrame(value: unknown, maximum: number): Buffer {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  if (payload.length > maximum) throw new Error("verification_worker_protocol_error");
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

export class WorkerFrameDecoder {
  private buffer = Buffer.alloc(0);
  constructor(private readonly maximum: number) {}
  push(chunk: Buffer): unknown | undefined {
    if (this.buffer.length + chunk.length > this.maximum + 4) throw new Error("verification_worker_protocol_error");
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (length < 2 || length > this.maximum || this.buffer.length > length + 4) throw new Error("verification_worker_protocol_error");
      if (this.buffer.length === length + 4) return JSON.parse(this.buffer.subarray(4).toString("utf8")) as unknown;
    }
    return undefined;
  }
}

export const INVARIANT_TIMEOUT_MS = 180_000;
export const INVARIANT_MAX_OUTPUT_BYTES = 2_097_152;
export const executableInvariantWorkerRequestSchema = z.object({
  command: z.literal("execute-invariant"), runId: uuid, workspaceId: uuid, scanId: uuid, hypothesisId: uuid,
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  planHash: z.string().regex(/^[a-f0-9]{64}$/), mode: z.enum(["fuzz-property", "stateful-invariant"]),
  timeoutMs: z.literal(INVARIANT_TIMEOUT_MS), maxOutputBytes: z.literal(INVARIANT_MAX_OUTPUT_BYTES),
}).strict().refine((request) => request.runId === request.workspaceId, "Workspace must match the invariant run.");
export const REPLAY_TIMEOUT_MS = 60_000;
export const REPLAY_MAX_OUTPUT_BYTES = 1_048_576;
export const invariantReplayWorkerRequestSchema = z.object({
  command: z.literal("execute-invariant-replay"), replayRunId: uuid, workspaceId: uuid, scanId: uuid, hypothesisId: uuid,
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), compilerVersion: z.string().regex(/^\d+\.\d+\.\d+$/), invariantPlanHash: z.string().regex(/^[a-f0-9]{64}$/), replayPlanHash: z.string().regex(/^[a-f0-9]{64}$/), counterexampleHash: z.string().regex(/^[a-f0-9]{64}$/),
  timeoutMs: z.literal(REPLAY_TIMEOUT_MS), maxOutputBytes: z.literal(REPLAY_MAX_OUTPUT_BYTES),
}).strict();
export const workerRequestSchema = z.union([verificationWorkerRequestSchema, executableInvariantWorkerRequestSchema, invariantReplayWorkerRequestSchema]);
export type ExecutableInvariantWorkerRequest = z.infer<typeof executableInvariantWorkerRequestSchema>;
export type InvariantReplayWorkerRequest = z.infer<typeof invariantReplayWorkerRequestSchema>;
export type WorkerRequest = z.infer<typeof workerRequestSchema>;
