import { randomUUID } from "node:crypto";
import { deriveImpactChanges, diffHash, impactChangeFrame, planEntries, provenanceFrame, snapshotHash,
  type ImpactObservation, type ImpactObservationKind, type ImpactObservationPlan,
  type ImpactStateDiff, type ImpactStateProvenance, type ImpactStateSnapshot } from "@contracthunter/core";

export type LocalStateRead = (method: string, params: unknown[]) => Promise<unknown>;
const CAPTURE_DEADLINE_MS = 20_000;
function hexInteger(value: unknown): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value) || value.length > 66) throw Error("invalid_response");
  return BigInt(value).toString();
}
function word(value: unknown): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw Error("invalid_response");
  return value.toLowerCase();
}
function uintWord(value: unknown): string { return BigInt(word(value)).toString(); }
function addressWord(value: unknown): string {
  const data = word(value);
  if (!/^0x0{24}[0-9a-f]{40}$/.test(data)) throw Error("invalid_response");
  return `0x${data.slice(-40)}`;
}
function paddedAddress(address: string): string { return address.slice(2).padStart(64, "0"); }
function paddedUint(value: string): string { return BigInt(value).toString(16).padStart(64, "0"); }

async function observe(kind: ImpactObservationKind, descriptor: Record<string, string>, tag: string,
  read: LocalStateRead): Promise<string> {
  switch (kind) {
    case "native": return hexInteger(await read("eth_getBalance", [descriptor.address, tag]));
    case "storage": return word(await read("eth_getStorageAt", [descriptor.contract, descriptor.slot, tag]));
    case "erc20": return uintWord(await read("eth_call", [{ to: descriptor.token,
      data: `0x70a08231${paddedAddress(descriptor.holder)}` }, tag]));
    case "erc721": return addressWord(await read("eth_call", [{ to: descriptor.token,
      data: `0x6352211e${paddedUint(descriptor.tokenId)}` }, tag]));
    case "erc1155": return uintWord(await read("eth_call", [{ to: descriptor.token,
      data: `0x00fdd58e${paddedAddress(descriptor.holder)}${paddedUint(descriptor.tokenId)}` }, tag]));
    case "view": return uintWord(await read("eth_call", [{ to: descriptor.target, data: "0x18160ddd" }, tag]));
  }
}
export async function captureImpactState(plan: ImpactObservationPlan, provenance: ImpactStateProvenance,
  phase: "pre" | "post", read: LocalStateRead): Promise<ImpactStateSnapshot> {
  const deadline = Date.now() + CAPTURE_DEADLINE_MS;
  const block = hexInteger(await read("eth_blockNumber", []));
  const blockNumber = Number(block);
  if (!Number.isSafeInteger(blockNumber)) throw Error("impact_state_block_invalid");
  const tag = `0x${BigInt(block).toString(16)}`;
  const context = await read("eth_getBlockByNumber", [tag, false]) as { timestamp?: unknown; number?: unknown } | null;
  if (!context || hexInteger(context.number) !== block || Date.now() > deadline) throw Error("impact_state_context_invalid");
  const timestamp = hexInteger(context.timestamp);
  const observations: ImpactObservation[] = [];
  for (const entry of planEntries(plan)) {
    if (Date.now() > deadline) throw Error("impact_state_capture_timeout");
    try {
      const value = await observe(entry.kind, entry.descriptor, tag, read);
      observations.push({ id: entry.id, kind: entry.kind, status: "available", value, errorCode: null });
    } catch (error) {
      if (error instanceof Error && ["impact_execution_endpoint_unsafe", "impact_session_identity_invalid",
        "impact_state_method_rejected"].includes(error.message)) throw error;
      observations.push({ id: entry.id, kind: entry.kind, status: "unavailable", value: null,
        errorCode: error instanceof Error && error.message === "invalid_response" ? "invalid_response" : "rpc_error" });
    }
  }
  if (Date.now() > deadline) throw Error("impact_state_capture_timeout");
  const snapshot: Omit<ImpactStateSnapshot, "contentSha256"> = { schema: "impact-state-snapshot-v1",
    id: randomUUID(), phase, provenance, observedAtBlock: blockNumber, observedAtTimestamp: timestamp, observations };
  return { ...snapshot, contentSha256: snapshotHash(snapshot) };
}

export function makeImpactStateDiff(pre: ImpactStateSnapshot, post: ImpactStateSnapshot): ImpactStateDiff {
  if (pre.phase !== "pre" || post.phase !== "post" || pre.schema !== "impact-state-snapshot-v1" ||
    post.schema !== "impact-state-snapshot-v1" || pre.contentSha256 !== snapshotHash(pre) ||
    post.contentSha256 !== snapshotHash(post) ||
    JSON.stringify(provenanceFrame(pre.provenance)) !== JSON.stringify(provenanceFrame(post.provenance)))
    throw Error("impact_state_binding_invalid");
  const changes = deriveImpactChanges(pre, post);
  const diff: Omit<ImpactStateDiff, "contentSha256"> = { schema: "impact-state-diff-v1", id: randomUUID(),
    provenance: pre.provenance, preSnapshotId: pre.id, postSnapshotId: post.id,
    preSnapshotSha256: pre.contentSha256, postSnapshotSha256: post.contentSha256,
    changes, changeCount: changes.length };
  return { ...diff, contentSha256: diffHash(diff) };
}

export function verifySnapshotShape(snapshot: ImpactStateSnapshot): void {
  if (snapshot.contentSha256 !== snapshotHash(snapshot) ||
    new Set(snapshot.observations.map((item) => item.id)).size !== snapshot.observations.length ||
    snapshot.observations.some((item) => item.status === "available" ? item.value === null || item.errorCode !== null :
      item.value !== null || item.errorCode === null)) throw Error("impact_state_integrity_failed");
}
export function verifyDiffShape(diff: ImpactStateDiff, pre: ImpactStateSnapshot, post: ImpactStateSnapshot): void {
  verifySnapshotShape(pre); verifySnapshotShape(post);
  if (diff.contentSha256 !== diffHash(diff) || diff.preSnapshotId !== pre.id || diff.postSnapshotId !== post.id ||
    diff.preSnapshotSha256 !== pre.contentSha256 || diff.postSnapshotSha256 !== post.contentSha256 ||
    diff.changeCount !== diff.changes.length ||
    JSON.stringify(provenanceFrame(diff.provenance)) !== JSON.stringify(provenanceFrame(pre.provenance)) ||
    JSON.stringify(provenanceFrame(pre.provenance)) !== JSON.stringify(provenanceFrame(post.provenance)))
    throw Error("impact_state_integrity_failed");
  // Recompute semantic changes, independent of stored rows.
  if (JSON.stringify(deriveImpactChanges(pre, post).map(impactChangeFrame)) !==
    JSON.stringify(diff.changes.map(impactChangeFrame))) throw Error("impact_state_integrity_failed");
}

