import { impactAddressSchema, impactForkStatusSchema, impactHashSchema, type ImpactForkSession } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

export function recordImpactForkSession(database: DatabaseClient, session: ImpactForkSession): void {
  impactForkStatusSchema.parse(session.status);
  if (!/^IMPACT_RPC_[A-Z0-9_]{1,64}$/.test(session.upstreamRpcRef) ||
    session.targetContracts.length < 1 || session.targetContracts.length > 20 ||
    session.targetContracts.some((address) => !impactAddressSchema.safeParse(address).success) ||
    session.disposableAccounts.some((address) => !impactAddressSchema.safeParse(address).success) ||
    session.forkBlockHash !== null && !impactHashSchema.safeParse(session.forkBlockHash).success ||
    session.historicalTransactionHash !== null && !impactHashSchema.safeParse(session.historicalTransactionHash).success) throw new Error("impact_session_invalid");
  const port = session.localPort;
  if (port !== null && (!Number.isInteger(port) || port < 1024 || port > 65535)) throw new Error("impact_session_invalid");
  if (session.localRpcEndpoint !== null && session.localRpcEndpoint !== `http://127.0.0.1:${port}`) throw new Error("impact_session_invalid");
  database.sqlite.prepare(`INSERT INTO impact_fork_sessions (
    id, finding_id, hypothesis_id, chain_id, network, upstream_rpc_ref, target_contracts,
    resolved_fork_block, historical_transaction_hash, fork_block_hash, status, local_port, anvil_version, anvil_sha256,
    process_pid, baseline_snapshot_id, disposable_accounts, created_at, started_at, stopped_at, failure_code
  ) VALUES (@id,@findingId,@hypothesisId,@chainId,@network,@upstreamRpcRef,@targetContracts,
    @resolvedForkBlock,@historicalTransactionHash,@forkBlockHash,@status,@localPort,@anvilVersion,@anvilSha256,
    @processPid,@baselineSnapshotId,@disposableAccounts,@createdAt,@startedAt,@stoppedAt,@failureCode)
  ON CONFLICT(id) DO UPDATE SET fork_block_hash=excluded.fork_block_hash, status=excluded.status,
    local_port=excluded.local_port, anvil_version=excluded.anvil_version, anvil_sha256=excluded.anvil_sha256,
    process_pid=excluded.process_pid, baseline_snapshot_id=excluded.baseline_snapshot_id,
    disposable_accounts=excluded.disposable_accounts, started_at=excluded.started_at,
    stopped_at=excluded.stopped_at, failure_code=excluded.failure_code`).run({
    ...session, targetContracts: JSON.stringify(session.targetContracts), disposableAccounts: JSON.stringify(session.disposableAccounts),
  });
}

export function recoverStaleImpactForkSessions(database: DatabaseClient): number {
  return database.sqlite.prepare("UPDATE impact_fork_sessions SET status='failed', failure_code='impact_server_restart', stopped_at=? WHERE status IN ('starting','ready','stopping')").run(Date.now()).changes;
}
