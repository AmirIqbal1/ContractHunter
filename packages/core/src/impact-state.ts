import { createHash } from "node:crypto";
import { z } from "zod";

const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/).transform((value) => value.toLowerCase());
const uint = z.string().regex(/^(?:0|[1-9][0-9]{0,77})$/).refine((value) => BigInt(value) < (1n << 256n));
const slot = z.string().regex(/^0x[0-9a-fA-F]{64}$/).transform((value) => value.toLowerCase());
const pair = z.object({ token: address, holder: address }).strict();
const nft = z.object({ token: address, tokenId: uint }).strict();
const multi = z.object({ token: address, holder: address, tokenId: uint }).strict();
const storage = z.object({ contract: address, slot }).strict();
const view = z.object({ kind: z.literal("erc20_totalSupply"), target: address }).strict();

export const impactObservationPlanInputSchema = z.object({
  nativeBalances: z.array(address).max(24).optional(),
  erc20Balances: z.array(pair).max(8).optional(),
  erc721Owners: z.array(nft).max(8).optional(),
  erc1155Balances: z.array(multi).max(8).optional(),
  storageSlots: z.array(storage).max(16).optional(),
  viewCalls: z.array(view).max(8).optional(),
}).strict();
export type ImpactObservationPlanInput = z.input<typeof impactObservationPlanInputSchema>;
export type ImpactObservationPlan = Readonly<{
  schema: "impact-observation-plan-v1";
  nativeBalances: string[];
  erc20Balances: Array<{ token: string; holder: string }>;
  erc721Owners: Array<{ token: string; tokenId: string }>;
  erc1155Balances: Array<{ token: string; holder: string; tokenId: string }>;
  storageSlots: Array<{ contract: string; slot: string }>;
  viewCalls: Array<{ kind: "erc20_totalSupply"; target: string }>;
}>;
export type ImpactObservationKind = "native" | "erc20" | "erc721" | "erc1155" | "storage" | "view";
export type ImpactObservation = Readonly<{ id: string; kind: ImpactObservationKind;
  status: "available" | "unavailable"; value: string | null; errorCode: "rpc_error" | "invalid_response" | null }>;
export type ImpactStateProvenance = Readonly<{ executionId: string; sessionId: string; runtimeTokenSha256: string;
  chainId: number; forkBlock: number; forkBlockHash: string; targetCodeHashes: Record<string, string>;
  artifactId: string; sourceSha256: string; planSha256: string }>;
export type ImpactStateSnapshot = Readonly<{ schema: "impact-state-snapshot-v1"; id: string; phase: "pre" | "post";
  provenance: ImpactStateProvenance; observedAtBlock: number; observedAtTimestamp: string;
  observations: ImpactObservation[]; contentSha256: string }>;
export type ImpactStateChange = Readonly<{ id: string; kind: ImpactObservationKind; type:
  "native_balance_changed" | "erc20_balance_changed" | "erc721_owner_changed" |
  "erc1155_balance_changed" | "storage_changed" | "view_value_changed";
  beforeStatus: "available" | "unavailable"; afterStatus: "available" | "unavailable";
  before: string | null; after: string | null; beforeErrorCode: string | null; afterErrorCode: string | null;
  delta: string | null }>;
export type ImpactStateDiff = Readonly<{ schema: "impact-state-diff-v1"; id: string;
  provenance: ImpactStateProvenance; preSnapshotId: string; postSnapshotId: string;
  preSnapshotSha256: string; postSnapshotSha256: string; changes: ImpactStateChange[];
  changeCount: number; contentSha256: string }>;

export function observationId(kind: ImpactObservationKind, descriptor: Record<string, string>): string {
  switch (kind) {
    case "native": return `native:${descriptor.address}`;
    case "erc20": return `erc20:${descriptor.token}:${descriptor.holder}`;
    case "erc721": return `erc721:${descriptor.token}:${descriptor.tokenId}`;
    case "erc1155": return `erc1155:${descriptor.token}:${descriptor.holder}:${descriptor.tokenId}`;
    case "storage": return `storage:${descriptor.contract}:${descriptor.slot}`;
    case "view": return `view:${descriptor.kind}:${descriptor.target}`;
  }
}
export function planEntries(plan: ImpactObservationPlan): Array<{ id: string; kind: ImpactObservationKind; descriptor: Record<string, string> }> {
  const entries: Array<{ id: string; kind: ImpactObservationKind; descriptor: Record<string, string> }> = [];
  for (const address of plan.nativeBalances) entries.push({ id: observationId("native", { address }), kind: "native", descriptor: { address } });
  for (const descriptor of plan.erc20Balances) entries.push({ id: observationId("erc20", descriptor), kind: "erc20", descriptor });
  for (const descriptor of plan.erc721Owners) entries.push({ id: observationId("erc721", descriptor), kind: "erc721", descriptor });
  for (const descriptor of plan.erc1155Balances) entries.push({ id: observationId("erc1155", descriptor), kind: "erc1155", descriptor });
  for (const descriptor of plan.storageSlots) entries.push({ id: observationId("storage", descriptor), kind: "storage", descriptor });
  for (const descriptor of plan.viewCalls) entries.push({ id: observationId("view", descriptor), kind: "view", descriptor });
  return entries.sort((a, b) => a.id.localeCompare(b.id));
}
export function makeImpactObservationPlan(sender: string, targets: string[], raw: unknown = {}): ImpactObservationPlan {
  const input = impactObservationPlanInputSchema.parse(raw);
  const normalizedSender = address.parse(sender);
  const normalizedTargets = targets.map((target) => address.parse(target));
  const allNative = [normalizedSender, ...normalizedTargets, ...(input.nativeBalances ?? [])];
  if (new Set(allNative).size !== allNative.length) throw Error("impact_observation_plan_invalid");
  const plan: ImpactObservationPlan = {
    schema: "impact-observation-plan-v1",
    nativeBalances: allNative.sort(),
    erc20Balances: input.erc20Balances ?? [], erc721Owners: input.erc721Owners ?? [],
    erc1155Balances: input.erc1155Balances ?? [], storageSlots: input.storageSlots ?? [], viewCalls: input.viewCalls ?? [],
  };
  const entries = planEntries(plan);
  if (plan.nativeBalances.length > 24 || entries.length > 64 || new Set(entries.map((entry) => entry.id)).size !== entries.length)
    throw Error("impact_observation_plan_invalid");
  return { ...plan,
    erc20Balances: [...plan.erc20Balances].sort((a, b) => observationId("erc20", a).localeCompare(observationId("erc20", b))),
    erc721Owners: [...plan.erc721Owners].sort((a, b) => observationId("erc721", a).localeCompare(observationId("erc721", b))),
    erc1155Balances: [...plan.erc1155Balances].sort((a, b) => observationId("erc1155", a).localeCompare(observationId("erc1155", b))),
    storageSlots: [...plan.storageSlots].sort((a, b) => observationId("storage", a).localeCompare(observationId("storage", b))),
    viewCalls: [...plan.viewCalls].sort((a, b) => observationId("view", a).localeCompare(observationId("view", b))) };
}
export function canonicalImpactHash(domain: string, fields: unknown[]): string {
  return `sha256:${createHash("sha256").update(domain).update("\0").update(JSON.stringify(fields)).digest("hex")}`;
}
export function provenanceFrame(value: ImpactStateProvenance): unknown[] {
  return [value.executionId, value.sessionId, value.runtimeTokenSha256, value.chainId, value.forkBlock,
    value.forkBlockHash, Object.entries(value.targetCodeHashes).sort(([a], [b]) => a.localeCompare(b)),
    value.artifactId, value.sourceSha256, value.planSha256];
}
export function observationFrame(value: ImpactObservation): unknown[] {
  return [value.id, value.kind, value.status, value.value, value.errorCode];
}
export function snapshotHash(value: Omit<ImpactStateSnapshot, "contentSha256">): string {
  return canonicalImpactHash(value.schema, [value.phase, provenanceFrame(value.provenance), value.observedAtBlock,
    value.observedAtTimestamp, [...value.observations].sort((a, b) => a.id.localeCompare(b.id)).map(observationFrame)]);
}
export function diffHash(value: Omit<ImpactStateDiff, "contentSha256">): string {
  return canonicalImpactHash(value.schema, [provenanceFrame(value.provenance), value.preSnapshotId,
    value.postSnapshotId, value.preSnapshotSha256, value.postSnapshotSha256,
    [...value.changes].sort((a, b) => a.id.localeCompare(b.id)).map((item) =>
      [item.id, item.kind, item.type, item.beforeStatus, item.afterStatus, item.before, item.after,
        item.beforeErrorCode, item.afterErrorCode, item.delta])]);
}
export function planHash(plan: ImpactObservationPlan): string {
  return canonicalImpactHash(plan.schema, planEntries(plan).map((entry) => [entry.id, entry.kind]));
}
const changeTypes: Record<ImpactObservationKind, ImpactStateChange["type"]> = {
  native: "native_balance_changed", erc20: "erc20_balance_changed", erc721: "erc721_owner_changed",
  erc1155: "erc1155_balance_changed", storage: "storage_changed", view: "view_value_changed",
};
export function deriveImpactChanges(pre: ImpactStateSnapshot, post: ImpactStateSnapshot): ImpactStateChange[] {
  const before = new Map(pre.observations.map((entry) => [entry.id, entry]));
  const after = new Map(post.observations.map((entry) => [entry.id, entry]));
  if (before.size !== pre.observations.length || after.size !== post.observations.length ||
    before.size !== after.size || [...before.keys()].some((id) => !after.has(id))) throw Error("impact_state_observations_invalid");
  const changes: ImpactStateChange[] = [];
  for (const [id, first] of [...before].sort(([a], [b]) => a.localeCompare(b))) {
    const last = after.get(id)!;
    if (first.kind !== last.kind) throw Error("impact_state_observations_invalid");
    if (first.status === last.status && first.value === last.value && first.errorCode === last.errorCode) continue;
    const numeric = ["native", "erc20", "erc1155"].includes(first.kind) && first.status === "available" && last.status === "available";
    changes.push({ id, kind: first.kind, type: changeTypes[first.kind], beforeStatus: first.status,
      afterStatus: last.status, before: first.value, after: last.value,
      beforeErrorCode: first.errorCode, afterErrorCode: last.errorCode,
      delta: numeric ? (BigInt(last.value!) - BigInt(first.value!)).toString() : null });
  }
  return changes;
}
export function impactChangeFrame(item: ImpactStateChange): unknown[] {
  return [item.id, item.kind, item.type, item.beforeStatus, item.afterStatus, item.before, item.after,
    item.beforeErrorCode, item.afterErrorCode, item.delta];
}
