import { deriveImpactChanges, diffHash, impactChangeFrame, planEntries, planHash, snapshotHash,
  type ImpactObservationPlan, type ImpactStateDiff,
  type ImpactStateProvenance, type ImpactStateSnapshot, type ImpactObservation, type ImpactStateChange } from "@contracthunter/core";
import type { DatabaseClient } from "./index";
import { readImpactPoCExecution } from "./impact-poc";

function provenance(row: Record<string, unknown>): ImpactStateProvenance {
  return { executionId: String(row.execution_id), sessionId: String(row.session_id),
    runtimeTokenSha256: String(row.runtime_token_sha256), chainId: Number(row.chain_id),
    forkBlock: Number(row.fork_block), forkBlockHash: String(row.fork_block_hash),
    targetCodeHashes: JSON.parse(String(row.target_code_hashes)) as Record<string, string>,
    artifactId: String(row.artifact_id), sourceSha256: String(row.source_sha256), planSha256: String(row.plan_sha256) };
}
function sameProvenance(a: ImpactStateProvenance, b: ImpactStateProvenance): boolean {
  return a.executionId === b.executionId && a.sessionId === b.sessionId &&
    a.runtimeTokenSha256 === b.runtimeTokenSha256 && a.chainId === b.chainId &&
    a.forkBlock === b.forkBlock && a.forkBlockHash === b.forkBlockHash &&
    a.artifactId === b.artifactId && a.sourceSha256 === b.sourceSha256 && a.planSha256 === b.planSha256 &&
    JSON.stringify(Object.entries(a.targetCodeHashes).sort()) === JSON.stringify(Object.entries(b.targetCodeHashes).sort());
}
function insertSnapshot(database: DatabaseClient, value: ImpactStateSnapshot): void {
  if (value.contentSha256 !== snapshotHash(value) || value.observations.length < 1 || value.observations.length > 64 ||
    new Set(value.observations.map((item) => item.id)).size !== value.observations.length)
    throw Error("impact_state_snapshot_invalid");
  const p = value.provenance;
  database.sqlite.prepare(`INSERT INTO impact_state_snapshots
    (id,schema,execution_id,phase,session_id,runtime_token_sha256,chain_id,fork_block,fork_block_hash,target_code_hashes,
      artifact_id,source_sha256,plan_sha256,observed_at_block,observed_at_timestamp,observation_count,content_sha256,status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'finalized')`).run(value.id, value.schema, p.executionId, value.phase,
    p.sessionId, p.runtimeTokenSha256, p.chainId, p.forkBlock, p.forkBlockHash, JSON.stringify(p.targetCodeHashes),
    p.artifactId, p.sourceSha256, p.planSha256, value.observedAtBlock, value.observedAtTimestamp,
    value.observations.length, value.contentSha256);
  const insert = database.sqlite.prepare(`INSERT INTO impact_state_observations
    (snapshot_id,identity,kind,status,value,error_code) VALUES (?,?,?,?,?,?)`);
  for (const observation of value.observations) insert.run(value.id, observation.id, observation.kind,
    observation.status, observation.value, observation.errorCode);
}
export function persistImpactStateArtifacts(database: DatabaseClient, plan: ImpactObservationPlan,
  pre: ImpactStateSnapshot, post: ImpactStateSnapshot | null, diff: ImpactStateDiff | null): void {
  database.sqlite.transaction(() => {
    const execution = readImpactPoCExecution(database, pre.provenance.executionId);
    const serializedPlan = JSON.stringify(plan);
    if (!execution || !["created", "running"].includes(execution.status) || serializedPlan.length > 16_384 ||
      pre.phase !== "pre" || pre.provenance.planSha256 !== planHash(plan) ||
      pre.provenance.sessionId !== execution.sessionId || pre.provenance.runtimeTokenSha256 !== execution.runtimeTokenSha256 ||
      pre.provenance.chainId !== execution.chainId || pre.provenance.forkBlock !== execution.forkBlock ||
      pre.provenance.forkBlockHash !== execution.forkBlockHash || pre.provenance.artifactId !== execution.artifactId ||
      pre.provenance.sourceSha256 !== execution.sourceSha256 ||
      JSON.stringify(Object.entries(pre.provenance.targetCodeHashes).sort()) !== JSON.stringify(Object.entries(execution.targetCodeHashes).sort()) ||
      Boolean(post) !== Boolean(diff)) throw Error("impact_state_binding_invalid");
    const expected = planEntries(plan).map((item) => item.id).join("\0");
    if (pre.observations.map((item) => item.id).sort().join("\0") !== expected) throw Error("impact_state_observations_invalid");
    if (post && diff) {
      if (post.phase !== "post" || !sameProvenance(pre.provenance, post.provenance) ||
        post.observations.map((item) => item.id).sort().join("\0") !== expected ||
        diff.provenance.executionId !== execution.id || !sameProvenance(diff.provenance, pre.provenance) ||
        diff.preSnapshotId !== pre.id || diff.postSnapshotId !== post.id ||
        diff.preSnapshotSha256 !== pre.contentSha256 || diff.postSnapshotSha256 !== post.contentSha256 ||
        diff.changeCount !== diff.changes.length || diff.contentSha256 !== diffHash(diff) ||
        JSON.stringify(diff.changes.map(impactChangeFrame)) !==
          JSON.stringify(deriveImpactChanges(pre, post).map(impactChangeFrame)))
        throw Error("impact_state_binding_invalid");
    }
    insertSnapshot(database, pre);
    if (post && diff) {
      insertSnapshot(database, post);
      database.sqlite.prepare(`INSERT INTO impact_state_diffs
        (id,schema,execution_id,pre_snapshot_id,post_snapshot_id,pre_snapshot_sha256,post_snapshot_sha256,
          change_count,content_sha256,status) VALUES (?,?,?,?,?,?,?,?,?,'finalized')`)
        .run(diff.id, diff.schema, execution.id, pre.id, post.id, pre.contentSha256, post.contentSha256,
          diff.changeCount, diff.contentSha256);
      const insert = database.sqlite.prepare(`INSERT INTO impact_state_changes
        (diff_id,identity,kind,type,before_status,after_status,before_value,after_value,before_error_code,after_error_code,delta)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
      for (const change of diff.changes) insert.run(diff.id, change.id, change.kind, change.type,
        change.beforeStatus, change.afterStatus, change.before, change.after, change.beforeErrorCode,
        change.afterErrorCode, change.delta);
    }
    if (database.sqlite.prepare(`UPDATE impact_poc_executions SET observation_plan=?,observation_plan_sha256=?,
      pre_snapshot_id=?,post_snapshot_id=?,state_diff_id=?,state_change_count=?
      WHERE id=? AND observation_plan IS NULL`).run(serializedPlan, planHash(plan), pre.id,
        post?.id ?? null, diff?.id ?? null, diff?.changeCount ?? null, execution.id).changes !== 1)
      throw Error("impact_state_already_persisted");
  })();
}
export function readImpactStateSnapshot(database: DatabaseClient, id: string): ImpactStateSnapshot | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_state_snapshots WHERE id=? AND status='finalized'").get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  const observations = (database.sqlite.prepare("SELECT * FROM impact_state_observations WHERE snapshot_id=? ORDER BY identity")
    .all(id) as Array<Record<string, unknown>>).map((item): ImpactObservation => ({ id: String(item.identity),
    kind: item.kind as ImpactObservation["kind"], status: item.status as ImpactObservation["status"],
    value: item.value as string | null, errorCode: item.error_code as ImpactObservation["errorCode"] }));
  const value: ImpactStateSnapshot = { schema: "impact-state-snapshot-v1", id, phase: row.phase as "pre" | "post",
    provenance: provenance(row), observedAtBlock: Number(row.observed_at_block),
    observedAtTimestamp: String(row.observed_at_timestamp), observations, contentSha256: String(row.content_sha256) };
  if (row.schema !== value.schema || observations.length !== Number(row.observation_count) ||
    new Set(observations.map((item) => item.id)).size !== observations.length || value.contentSha256 !== snapshotHash(value))
    throw Error("impact_state_integrity_failed");
  return value;
}
export function readImpactStateDiff(database: DatabaseClient, id: string): ImpactStateDiff | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_state_diffs WHERE id=? AND status='finalized'").get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  const pre = readImpactStateSnapshot(database, String(row.pre_snapshot_id));
  const post = readImpactStateSnapshot(database, String(row.post_snapshot_id));
  if (!pre || !post || pre.phase !== "pre" || post.phase !== "post" ||
    pre.provenance.executionId !== row.execution_id || post.provenance.executionId !== row.execution_id ||
    !sameProvenance(pre.provenance, post.provenance)) throw Error("impact_state_integrity_failed");
  const changes = (database.sqlite.prepare("SELECT * FROM impact_state_changes WHERE diff_id=? ORDER BY identity")
    .all(id) as Array<Record<string, unknown>>).map((item): ImpactStateChange => ({ id: String(item.identity),
    kind: item.kind as ImpactStateChange["kind"], type: item.type as ImpactStateChange["type"],
    beforeStatus: item.before_status as ImpactStateChange["beforeStatus"], afterStatus: item.after_status as ImpactStateChange["afterStatus"],
    before: item.before_value as string | null, after: item.after_value as string | null,
    beforeErrorCode: item.before_error_code as string | null, afterErrorCode: item.after_error_code as string | null,
    delta: item.delta as string | null }));
  const value: ImpactStateDiff = { schema: "impact-state-diff-v1", id, provenance: pre.provenance,
    preSnapshotId: pre.id, postSnapshotId: post.id, preSnapshotSha256: String(row.pre_snapshot_sha256),
    postSnapshotSha256: String(row.post_snapshot_sha256), changes, changeCount: Number(row.change_count),
    contentSha256: String(row.content_sha256) };
  if (row.schema !== value.schema || changes.length !== value.changeCount ||
    new Set(changes.map((item) => item.id)).size !== changes.length ||
    value.preSnapshotSha256 !== pre.contentSha256 || value.postSnapshotSha256 !== post.contentSha256 ||
    value.contentSha256 !== diffHash(value) ||
    JSON.stringify(value.changes.map(impactChangeFrame)) !==
      JSON.stringify(deriveImpactChanges(pre, post).map(impactChangeFrame))) throw Error("impact_state_integrity_failed");
  return value;
}
export function readImpactExecutionState(database: DatabaseClient, executionId: string) {
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution) return null;
  const pre = execution.preSnapshotId ? readImpactStateSnapshot(database, execution.preSnapshotId) : null;
  const post = execution.postSnapshotId ? readImpactStateSnapshot(database, execution.postSnapshotId) : null;
  const diff = execution.stateDiffId ? readImpactStateDiff(database, execution.stateDiffId) : null;
  const expected = execution.observationPlan ? {
    executionId, sessionId: execution.sessionId, runtimeTokenSha256: execution.runtimeTokenSha256,
    chainId: execution.chainId, forkBlock: execution.forkBlock, forkBlockHash: execution.forkBlockHash,
    targetCodeHashes: execution.targetCodeHashes, artifactId: execution.artifactId,
    sourceSha256: execution.sourceSha256, planSha256: execution.observationPlanSha256!,
  } : null;
  const identities = execution.observationPlan ? planEntries(execution.observationPlan).map((entry) => entry.id).join("\0") : null;
  if (pre && (!expected || !sameProvenance(pre.provenance, expected) ||
      pre.observations.map((item) => item.id).sort().join("\0") !== identities) ||
    post && (!expected || !sameProvenance(post.provenance, expected) ||
      post.observations.map((item) => item.id).sort().join("\0") !== identities) ||
    diff && (!expected || !sameProvenance(diff.provenance, expected)) ||
    diff && (diff.preSnapshotId !== execution.preSnapshotId || diff.postSnapshotId !== execution.postSnapshotId) ||
    execution.observationPlan && execution.observationPlanSha256 !== planHash(execution.observationPlan) ||
    execution.stateChangeCount !== (diff?.changeCount ?? null) ||
    Boolean(execution.postSnapshotId) !== Boolean(execution.stateDiffId))
    throw Error("impact_state_integrity_failed");
  return { executionId, plan: execution.observationPlan, pre, post, diff };
}
