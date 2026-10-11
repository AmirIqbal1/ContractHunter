import { randomUUID } from "node:crypto";
import { impactPoCCreateSchema, impactPoCSourceHash, type ImpactObservationPlan,
  type ImpactPoCReviewState, type ImpactPoCExecutionStatus } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

export type ImpactPoCArtifact = Readonly<{ id: string; findingId: string | null; hypothesisId: string | null;
  revisionOf: string | null; filename: "ImpactPoC.s.sol"; source: string; sourceSha256: string;
  entryContract: string; origin: "manual"; reviewState: ImpactPoCReviewState;
  createdAt: number; reviewedAt: number | null }>;
export type ImpactPoCExecution = Readonly<{ id: string; artifactId: string; sourceSha256: string;
  sessionId: string; runtimeTokenSha256: string; chainId: number; forkBlock: number; forkBlockHash: string;
  targetCodeHashes: Record<string, string>; forgeVersion: string | null; forgeSha256: string | null;
  status: ImpactPoCExecutionStatus; createdAt: number; startedAt: number | null; completedAt: number | null;
  exitCode: number | null; compiled: boolean; executed: boolean; transactionScope: "local-impact-lab";
  stdout: string | null; stderr: string | null; transactionHashes: string[];
  errorCode: string | null; observationPlan: ImpactObservationPlan | null;
  observationPlanSha256: string | null; preSnapshotId: string | null; postSnapshotId: string | null;
  stateDiffId: string | null; stateChangeCount: number | null; stateCaptureAvailable: boolean }>;
function artifact(row: Record<string, unknown>): ImpactPoCArtifact {
  return { id: String(row.id), findingId: row.finding_id as string | null, hypothesisId: row.hypothesis_id as string | null,
    revisionOf: row.revision_of as string | null, filename: "ImpactPoC.s.sol", source: String(row.source),
    sourceSha256: String(row.source_sha256), entryContract: String(row.entry_contract), origin: "manual",
    reviewState: row.review_state as ImpactPoCReviewState, createdAt: Number(row.created_at), reviewedAt: row.reviewed_at as number | null };
}
function execution(row: Record<string, unknown>): ImpactPoCExecution {
  return { id: String(row.id), artifactId: String(row.artifact_id), sourceSha256: String(row.source_sha256),
    sessionId: String(row.session_id), runtimeTokenSha256: String(row.runtime_token_sha256),
    chainId: Number(row.chain_id), forkBlock: Number(row.fork_block), forkBlockHash: String(row.fork_block_hash),
    targetCodeHashes: JSON.parse(String(row.target_code_hashes)) as Record<string, string>,
    forgeVersion: row.forge_version as string | null, forgeSha256: row.forge_sha256 as string | null,
    status: row.status as ImpactPoCExecutionStatus, createdAt: Number(row.created_at),
    startedAt: row.started_at as number | null, completedAt: row.completed_at as number | null,
    exitCode: row.exit_code as number | null, compiled: Boolean(row.compiled), executed: Boolean(row.executed),
    transactionScope: row.transaction_scope as "local-impact-lab", stdout: row.stdout as string | null, stderr: row.stderr as string | null,
    transactionHashes: JSON.parse(String(row.transaction_hashes)) as string[], errorCode: row.error_code as string | null,
    observationPlan: row.observation_plan ? JSON.parse(String(row.observation_plan)) as ImpactObservationPlan : null,
    observationPlanSha256: row.observation_plan_sha256 as string | null,
    preSnapshotId: row.pre_snapshot_id as string | null, postSnapshotId: row.post_snapshot_id as string | null,
    stateDiffId: row.state_diff_id as string | null, stateChangeCount: row.state_change_count as number | null,
    stateCaptureAvailable: row.state_diff_id !== null };
}
export function createImpactPoCArtifact(database: DatabaseClient, raw: unknown): ImpactPoCArtifact {
  const input = impactPoCCreateSchema.parse(raw);
  const identityTable = input.findingId ? "findings" : "vulnerability_hypotheses";
  if (!database.sqlite.prepare(`SELECT 1 FROM ${identityTable} WHERE id=?`).get(input.findingId ?? input.hypothesisId)) throw Error("impact_poc_parent_missing");
  if (input.revisionOf) {
    const previous = readImpactPoCArtifact(database, input.revisionOf);
    if (!previous || previous.findingId !== (input.findingId ?? null) || previous.hypothesisId !== (input.hypothesisId ?? null))
      throw Error("impact_poc_revision_invalid");
  }
  const id = randomUUID(), createdAt = Date.now(), sourceSha256 = impactPoCSourceHash(input.source);
  database.sqlite.prepare(`INSERT INTO impact_poc_artifacts
    (id,finding_id,hypothesis_id,revision_of,filename,source,source_sha256,entry_contract,origin,review_state,created_at)
    VALUES (?,?,?,?,?,?,?,?, 'manual','draft',?)`).run(id, input.findingId ?? null, input.hypothesisId ?? null,
    input.revisionOf ?? null, input.filename, input.source, sourceSha256, input.entryContract, createdAt);
  return readImpactPoCArtifact(database, id)!;
}
export function readImpactPoCArtifact(database: DatabaseClient, id: string): ImpactPoCArtifact | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_poc_artifacts WHERE id=?").get(id) as Record<string, unknown> | undefined;
  return row ? artifact(row) : null;
}
export function reviewImpactPoCArtifact(database: DatabaseClient, id: string, decision: "reviewed" | "rejected"): ImpactPoCArtifact {
  if (!database.sqlite.prepare("UPDATE impact_poc_artifacts SET review_state=?,reviewed_at=? WHERE id=? AND review_state='draft'")
    .run(decision, Date.now(), id).changes) throw Error("impact_poc_not_draft");
  return readImpactPoCArtifact(database, id)!;
}
export function createImpactPoCExecution(database: DatabaseClient, input: Omit<ImpactPoCExecution, "status" | "createdAt" | "startedAt" | "completedAt" | "exitCode" | "compiled" | "executed" | "transactionScope" | "stdout" | "stderr" | "transactionHashes" | "errorCode" | "observationPlan" | "observationPlanSha256" | "preSnapshotId" | "postSnapshotId" | "stateDiffId" | "stateChangeCount" | "stateCaptureAvailable">): ImpactPoCExecution {
  const createdAt = Date.now();
  database.sqlite.prepare(`INSERT INTO impact_poc_executions
    (id,artifact_id,source_sha256,session_id,runtime_token_sha256,chain_id,fork_block,fork_block_hash,target_code_hashes,forge_version,forge_sha256,status,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,'created',?)`).run(input.id, input.artifactId, input.sourceSha256, input.sessionId,
    input.runtimeTokenSha256, input.chainId, input.forkBlock, input.forkBlockHash,
    JSON.stringify(input.targetCodeHashes), input.forgeVersion, input.forgeSha256, createdAt);
  return readImpactPoCExecution(database, input.id)!;
}
export function readImpactPoCExecution(database: DatabaseClient, id: string): ImpactPoCExecution | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_poc_executions WHERE id=?").get(id) as Record<string, unknown> | undefined;
  return row ? execution(row) : null;
}
export function updateImpactPoCExecution(database: DatabaseClient, id: string, status: ImpactPoCExecutionStatus,
  result?: { exitCode: number | null; compiled: boolean; executed: boolean; stdout: string; stderr: string; transactionHashes: string[]; errorCode: string | null;
    forgeVersion: string; forgeSha256: string }): ImpactPoCExecution {
  if (!database.sqlite.prepare(`UPDATE impact_poc_executions SET status=?,started_at=COALESCE(started_at,?),
    completed_at=?,exit_code=?,compiled=?,executed=?,stdout=?,stderr=?,transaction_hashes=?,error_code=?,forge_version=COALESCE(?,forge_version),forge_sha256=COALESCE(?,forge_sha256)
    WHERE id=? AND status IN ('created','queued','running')`).run(status, Date.now(),
    ["completed", "failed", "cancelled"].includes(status) ? Date.now() : null,
    result?.exitCode ?? null, result?.compiled ? 1 : 0, result?.executed ? 1 : 0,
    result?.stdout.slice(0, 8192) ?? null, result?.stderr.slice(0, 8192) ?? null,
    JSON.stringify(result?.transactionHashes.slice(0, 4) ?? []), result?.errorCode ?? null,
    result?.forgeVersion ?? null, result?.forgeSha256 ?? null, id).changes) throw Error("impact_execution_state_invalid");
  return readImpactPoCExecution(database, id)!;
}
