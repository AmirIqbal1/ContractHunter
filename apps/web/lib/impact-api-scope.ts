import { getFinding, getScan, getVulnerabilityHypothesis, readImpactForkSession,
  readImpactPoCArtifact, readImpactPoCExecution, type DatabaseClient } from "@contracthunter/db";
import { idSchema } from "./api";
import { containsSensitiveExportText } from "@contracthunter/core";

export function requestedImpactScan(request: Request): string | null {
  const scanId = new URL(request.url).searchParams.get("scanId");
  return scanId && idSchema.safeParse(scanId).success ? scanId : null;
}

export function impactSubjectInScan(database: DatabaseClient, scanId: string,
  findingId: string | null, hypothesisId: string | null): boolean {
  if (!getScan(database, scanId) || Number(Boolean(findingId)) + Number(Boolean(hypothesisId)) !== 1) return false;
  const subject = findingId ? getFinding(database, findingId) : getVulnerabilityHypothesis(database, hypothesisId!);
  return subject?.scanId === scanId;
}

export function scopedImpactSession(database: DatabaseClient, scanId: string, sessionId: string) {
  const session = readImpactForkSession(database, sessionId);
  return session && impactSubjectInScan(database, scanId, session.findingId, session.hypothesisId) ? session : null;
}

export function scopedImpactPoC(database: DatabaseClient, scanId: string, pocId: string) {
  const poc = readImpactPoCArtifact(database, pocId);
  return poc && impactSubjectInScan(database, scanId, poc.findingId, poc.hypothesisId) ? poc : null;
}

export function publicImpactPoC(poc: NonNullable<ReturnType<typeof readImpactPoCArtifact>>) {
  const sourceOmitted = containsSensitiveExportText(poc.source);
  return { id: poc.id, findingId: poc.findingId, hypothesisId: poc.hypothesisId,
    revisionOf: poc.revisionOf, filename: poc.filename, source: sourceOmitted ? null : poc.source,
    sourceOmitted, sourceSha256: poc.sourceSha256, entryContract: poc.entryContract,
    origin: poc.origin, reviewState: poc.reviewState, createdAt: poc.createdAt, reviewedAt: poc.reviewedAt };
}

export function scopedImpactExecution(database: DatabaseClient, scanId: string, executionId: string) {
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution) return null;
  const poc = scopedImpactPoC(database, scanId, execution.artifactId);
  const session = scopedImpactSession(database, scanId, execution.sessionId);
  return poc && session && poc.findingId === session.findingId && poc.hypothesisId === session.hypothesisId ?
    execution : null;
}

export function publicImpactExecution(execution: NonNullable<ReturnType<typeof readImpactPoCExecution>>) {
  return { id: execution.id, artifactId: execution.artifactId, sourceSha256: execution.sourceSha256,
    sessionId: execution.sessionId, chainId: execution.chainId, forkBlock: execution.forkBlock,
    forkBlockHash: execution.forkBlockHash, targetCodeHashes: execution.targetCodeHashes,
    forgeVersion: execution.forgeVersion, forgeSha256: execution.forgeSha256, status: execution.status,
    createdAt: execution.createdAt, startedAt: execution.startedAt, completedAt: execution.completedAt,
    exitCode: execution.exitCode, compiled: execution.compiled, executed: execution.executed,
    transactionScope: execution.transactionScope, transactionHashes: execution.transactionHashes,
    errorCode: execution.errorCode, observationPlan: execution.observationPlan,
    observationPlanSha256: execution.observationPlanSha256, preSnapshotId: execution.preSnapshotId,
    postSnapshotId: execution.postSnapshotId, stateDiffId: execution.stateDiffId,
    stateChangeCount: execution.stateChangeCount, stateCaptureAvailable: execution.stateCaptureAvailable,
    traceCaptureStatus: execution.traceCaptureStatus, traceCount: execution.traceCount,
    traceNodeCount: execution.traceNodeCount, traceErrorCode: execution.traceErrorCode,
    traceAvailable: execution.traceAvailable, traceIds: execution.traceIds };
}
