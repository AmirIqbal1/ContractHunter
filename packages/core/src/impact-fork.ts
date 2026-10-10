import { z } from "zod";

export const impactAddressSchema = z.string().regex(/^0x[a-fA-F0-9]{40}$/);
export const impactHashSchema = z.string().regex(/^0x[a-fA-F0-9]{64}$/);
export const impactForkConfigSchema = z.object({
  chainId: z.number().int().positive().safe().max(1_000_000_000_000),
  network: z.string().min(1).max(64).regex(/^[a-z0-9][a-z0-9-]*$/),
  upstreamRpcRef: z.string().regex(/^IMPACT_RPC_[A-Z0-9_]{1,64}$/),
  targetContracts: z.array(impactAddressSchema).min(1).max(20),
  forkBlock: z.number().int().nonnegative().safe(),
  findingId: z.string().uuid().optional(),
  hypothesisId: z.string().uuid().optional(),
  historicalTransactionHash: impactHashSchema.optional(),
  localBindAddress: z.literal("127.0.0.1").default("127.0.0.1"),
}).strict().refine((value) => Number(Boolean(value.findingId)) + Number(Boolean(value.hypothesisId)) === 1,
  "Exactly one finding or hypothesis ID is required.");

export type ImpactForkConfig = z.infer<typeof impactForkConfigSchema>;
export const impactForkStatusSchema = z.enum(["created", "starting", "ready", "failed", "stopping", "stopped"]);
export type ImpactForkStatus = z.infer<typeof impactForkStatusSchema>;
export type ImpactForkSession = Readonly<{
  id: string; status: ImpactForkStatus; findingId: string | null; hypothesisId: string | null;
  chainId: number; network: string; upstreamRpcRef: string; targetContracts: string[];
  resolvedForkBlock: number; historicalTransactionHash: string | null; forkBlockHash: string | null;
  localPort: number | null; localRpcEndpoint: string | null;
  anvilVersion: string | null; anvilSha256: string | null; processPid: number | null;
  baselineSnapshotId: string | null; disposableAccounts: string[];
  createdAt: number; startedAt: number | null; stoppedAt: number | null; failureCode: string | null;
}>;

// This is a positive policy. Browser input cannot extend either set.
export const UPSTREAM_READ_METHODS = Object.freeze([
  "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getBlockByHash",
  "eth_getCode", "eth_getBalance", "eth_call", "eth_getStorageAt", "eth_getLogs",
  "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getTransactionCount",
  "eth_getProof", "eth_feeHistory", "eth_gasPrice", "eth_maxPriorityFeePerGas",
  "eth_getBlockReceipts", "net_version",
] as const);
const upstreamReadMethodSet: ReadonlySet<string> = new Set(UPSTREAM_READ_METHODS);

export const LOCAL_IMPACT_METHODS = Object.freeze([
  "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "web3_clientVersion",
  "eth_accounts", "evm_snapshot", "evm_revert", "anvil_impersonateAccount",
  "anvil_stopImpersonatingAccount",
] as const);
const localImpactMethodSet: ReadonlySet<string> = new Set(LOCAL_IMPACT_METHODS);

export function assertUpstreamReadMethod(method: string): void {
  if (!upstreamReadMethodSet.has(method)) throw new Error("impact_upstream_method_forbidden");
}

export function assertLocalImpactMethod(method: string): void {
  if (!localImpactMethodSet.has(method)) throw new Error("impact_local_method_forbidden");
}
