// Execution facts returned by the network-isolated verification worker.
// The web application alone interprets these facts and updates hypothesis state.
export type FoundryVerificationInput = {
  workspacePath: string;
  scanId: string;
  hypothesisId: string;
  resolvedCommit: string;
  compilerVersion: string;
  timeoutMs: number;
  maxOutputBytes: number;
  matchTest?: string;
};

export type VerificationResourceLimits = {
  maxCpuTimeSeconds: number;
  maxVirtualMemoryBytes: number;
  maxProcesses: number;
  maxOpenFiles: number;
  maxFileSizeBytes: number;
};

export type VerificationIsolationMetadata = {
  providerId: "docker-verification-worker-v1" | string;
  isolationVersion: string;
  networkAccess: "disabled";
  networkIsolated: true;
  processIsolated: true;
  resourceLimitsApplied: VerificationResourceLimits;
  wallClockTimeoutMs: number;
  maxOutputBytes: number;
  writableProjectPath: string;
  workerUid?: number;
};

export type FoundryVerificationErrorCode =
  | "invalid_input"
  | "invalid_workspace"
  | "invalid_manifest"
  | "manifest_mismatch"
  | "unsafe_configuration"
  | "trusted_compiler_unavailable"
  | "forge_failed"
  | "verification_worker_unavailable"
  | "verification_worker_isolation_unavailable"
  | "verification_worker_protocol_error"
  | "verification_worker_timeout";

export type FoundryVerificationResult = {
  status: "completed" | "failed" | "refused";
  exitCode: number | null;
  durationMs: number;
  timedOut: boolean;
  testCount: number | null;
  passedCount: number | null;
  failedCount: number | null;
  stdoutSummary: string;
  stderrSummary: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  outputTruncated: boolean;
  errorCode: FoundryVerificationErrorCode | null;
  errorMessage: string | null;
  isolation: VerificationIsolationMetadata | null;
  compilerIdentity?: { version: string; executablePath: string };
};
