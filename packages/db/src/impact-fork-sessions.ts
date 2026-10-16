import { impactAddressSchema, impactForkStatusSchema, impactHashSchema, impactRpcConfigIdSchema, type ImpactForkSession } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

export function recordImpactForkSession(database: DatabaseClient, session: ImpactForkSession): void {
  impactForkStatusSchema.parse(session.status);
  if (!/^IMPACT_RPC_[A-Z0-9_]{1,64}$/.test(session.upstreamRpcRef) ||
    session.targetContracts.length < 1 || session.targetContracts.length > 20 ||
    session.targetContracts.some((address) => !impactAddressSchema.safeParse(address).success) ||
    session.rpcConfigId !== null && !impactRpcConfigIdSchema.safeParse(session.rpcConfigId).success ||
    Object.keys(session.targetCodeHashes).some((address) => !session.targetContracts.includes(address) || !/^sha256:[0-9a-f]{64}$/.test(session.targetCodeHashes[address] ?? "")) ||
    session.status === "ready" && (session.forkBlockHash === null || session.targetContracts.some((address) => !session.targetCodeHashes[address])) ||
    session.disposableAccounts.some((address) => !impactAddressSchema.safeParse(address).success) ||
    session.forkBlockHash !== null && !impactHashSchema.safeParse(session.forkBlockHash).success ||
    session.historicalTransactionHash !== null && !impactHashSchema.safeParse(session.historicalTransactionHash).success) throw new Error("impact_session_invalid");
  const port = session.localPort;
  if (port !== null && (!Number.isInteger(port) || port < 1024 || port > 65535)) throw new Error("impact_session_invalid");
  if (session.localRpcEndpoint !== null && session.localRpcEndpoint !== `http://127.0.0.1:${port}`) throw new Error("impact_session_invalid");
  database.sqlite.prepare(`INSERT INTO impact_fork_sessions (
    id, finding_id, hypothesis_id, chain_id, network, upstream_rpc_ref, target_contracts,
    resolved_fork_block, historical_transaction_hash, fork_block_hash, status, local_port, anvil_version, anvil_sha256,
    process_pid, baseline_snapshot_id, disposable_accounts, created_at, started_at, stopped_at, failure_code, rpc_config_id, target_code_hashes
  ) VALUES (@id,@findingId,@hypothesisId,@chainId,@network,@upstreamRpcRef,@targetContracts,
    @resolvedForkBlock,@historicalTransactionHash,@forkBlockHash,@status,@localPort,@anvilVersion,@anvilSha256,
    @processPid,@baselineSnapshotId,@disposableAccounts,@createdAt,@startedAt,@stoppedAt,@failureCode,@rpcConfigId,@targetCodeHashes)
  ON CONFLICT(id) DO UPDATE SET fork_block_hash=excluded.fork_block_hash, status=excluded.status,
    local_port=excluded.local_port, anvil_version=excluded.anvil_version, anvil_sha256=excluded.anvil_sha256,
    process_pid=excluded.process_pid, baseline_snapshot_id=excluded.baseline_snapshot_id,
    disposable_accounts=excluded.disposable_accounts, started_at=excluded.started_at,
    stopped_at=excluded.stopped_at, failure_code=excluded.failure_code,
    target_code_hashes=excluded.target_code_hashes`).run({
    ...session, targetContracts: JSON.stringify(session.targetContracts), disposableAccounts: JSON.stringify(session.disposableAccounts),
    targetCodeHashes: Object.keys(session.targetCodeHashes).length ? JSON.stringify(session.targetCodeHashes) : null,
  });
}

export function recoverStaleImpactForkSessions(database: DatabaseClient): number {
  return database.sqlite.prepare("UPDATE impact_fork_sessions SET status='failed', failure_code='impact_server_restart', stopped_at=? WHERE status IN ('starting','ready','stopping')").run(Date.now()).changes;
}

export function readImpactForkSession(database: DatabaseClient, id: string): ImpactForkSession | null {
  const row = database.sqlite.prepare("SELECT * FROM impact_fork_sessions WHERE id=?").get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  return {
    id: String(row.id), status: impactForkStatusSchema.parse(row.status), findingId: row.finding_id as string | null,
    hypothesisId: row.hypothesis_id as string | null, chainId: Number(row.chain_id), network: String(row.network),
    upstreamRpcRef: String(row.upstream_rpc_ref), rpcConfigId: row.rpc_config_id as string | null,
    targetContracts: JSON.parse(String(row.target_contracts)) as string[],
    targetCodeHashes: row.target_code_hashes ? JSON.parse(String(row.target_code_hashes)) as Record<string, string> : {},
    resolvedForkBlock: Number(row.resolved_fork_block), historicalTransactionHash: row.historical_transaction_hash as string | null,
    forkBlockHash: row.fork_block_hash as string | null, localPort: row.local_port as number | null,
    localRpcEndpoint: row.local_port === null || !["ready", "starting"].includes(String(row.status)) ? null : `http://127.0.0.1:${row.local_port}`,
    anvilVersion: row.anvil_version as string | null, anvilSha256: row.anvil_sha256 as string | null,
    processPid: row.process_pid as number | null, baselineSnapshotId: row.baseline_snapshot_id as string | null,
    disposableAccounts: JSON.parse(String(row.disposable_accounts)) as string[], createdAt: Number(row.created_at),
    startedAt: row.started_at as number | null, stoppedAt: row.stopped_at as number | null,
    failureCode: row.failure_code as string | null,
  };
}
