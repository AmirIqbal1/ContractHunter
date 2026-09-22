import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VerificationWorkerClient } from "./verification-worker-client";
import { encodeWorkerFrame, verificationWorkerRequestSchema, WorkerFrameDecoder, WORKER_REQUEST_MAX_BYTES } from "./verification-worker-protocol";
import { executeVerification, isolationPreflight } from "../../../docker/verification-worker";

const runId = "33333333-3333-4333-8333-333333333333";
const scanId = "11111111-1111-4111-8111-111111111111";
const hypothesisId = "22222222-2222-4222-8222-222222222222";
const request = { command: "verify", verificationRunId: runId, workspaceId: runId, scanId, hypothesisId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", timeoutMs: 5_000, maxOutputBytes: 8_192 };
let root: string;
let socketPath: string;

beforeEach(async () => { root = await mkdtemp(path.join(tmpdir(), "contracthunter-worker-client-")); await mkdir(path.join(root, runId)); socketPath = path.join(root, "worker.sock"); });
afterEach(async () => { await rm(root, { recursive: true, force: true }); });

function input() { return { workspacePath: path.join(root, runId), scanId, hypothesisId, resolvedCommit: "a".repeat(40), compilerVersion: "0.8.36", timeoutMs: 5_000, maxOutputBytes: 8_192 }; }

describe("bounded verification worker protocol", () => {
  it("accepts only the fixed verification command and rejects paths, arguments, and unknown fields", () => {
    expect(verificationWorkerRequestSchema.safeParse(request).success).toBe(true);
    for (const changed of [
      { command: "shell" }, { workspaceId: "../repository" }, { workspaceId: "/data/repositories" }, { workspaceId: scanId },
      { forgeArgs: ["--ffi"] }, { executable: "/bin/sh" }, { compilerPath: "/tmp/solc" }, { compilerVersion: "../solc" },
      { matchTest: "testX --ffi" }, { resolvedCommit: "main" }, { timeoutMs: 1_800_001 }, { maxOutputBytes: 20_971_521 },
    ]) expect(verificationWorkerRequestSchema.safeParse({ ...request, ...changed }).success).toBe(false);
    expect(verificationWorkerRequestSchema.safeParse({ ...request, matchTest: "testSafeName" }).success).toBe(true);
  });

  it("frames messages with a bounded length and rejects extra or oversized bytes", () => {
    const frame = encodeWorkerFrame(request, WORKER_REQUEST_MAX_BYTES);
    const decoder = new WorkerFrameDecoder(WORKER_REQUEST_MAX_BYTES);
    expect(decoder.push(frame.subarray(0, 3))).toBeUndefined();
    expect(decoder.push(frame.subarray(3))).toEqual(request);
    expect(() => encodeWorkerFrame({ source: "x".repeat(5_000) }, WORKER_REQUEST_MAX_BYTES)).toThrow();
    expect(() => new WorkerFrameDecoder(WORKER_REQUEST_MAX_BYTES).push(Buffer.alloc(WORKER_REQUEST_MAX_BYTES + 5))).toThrow();
    expect(() => new WorkerFrameDecoder(WORKER_REQUEST_MAX_BYTES).push(Buffer.concat([frame, Buffer.from("x")]))).toThrow();
  });

  it("fails closed when the socket is absent and never invokes a web Forge fallback", async () => {
    expect(await new VerificationWorkerClient(root, socketPath).run(input())).toMatchObject({ status: "refused", errorCode: "verification_worker_unavailable", isolation: null });
  });

  it("rejects a workspace outside the shared verification root before socket contact", async () => {
    expect(await new VerificationWorkerClient(root, socketPath).run({ ...input(), workspacePath: path.dirname(root) })).toMatchObject({ status: "refused", errorCode: "invalid_input" });
  });

  it("refuses execution when the worker identity and isolation preflight have not passed", async () => {
    await expect(isolationPreflight()).rejects.toThrow("worker identity is unavailable");
    await expect(executeVerification(verificationWorkerRequestSchema.parse(request))).rejects.toThrow("worker identity is unavailable");
  });

});
