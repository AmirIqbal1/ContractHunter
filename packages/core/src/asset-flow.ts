import { canonicalImpactHash } from "./impact-state";
import { keccak256 } from "./impact-selector";
import type { ImpactOverlay, ObservedOverlayCall, ObservedOverlayLog } from "./impact-overlay";

export const ASSET_FLOW_SCHEMA = "contracthunter-asset-flow-v1" as const;
export const ASSET_ACCOUNTING_RULESET = "contracthunter-asset-accounting-v1" as const;
const TRANSFER = keccak256("Transfer(address,address,uint256)");
const SINGLE = keccak256("TransferSingle(address,address,address,uint256,uint256)");
const BATCH = keccak256("TransferBatch(address,address,address,uint256[],uint256[])");
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ZERO = `0x${"0".repeat(40)}`;
const MAX_BATCH = 32;

export type AssetStandard = "native" | "erc20" | "erc721" | "erc1155" | "token-unknown-standard";
export type TrustedAssetStandard = Readonly<{ address: string; standard: "erc20" | "erc721" | "erc1155";
  evidenceId: string }>;
export type AssetFlowEntry = Readonly<{ id: string; transactionHash: string; transactionOrdinal: number;
  assetId: string; standard: AssetStandard; from: string; to: string; amount: string;
  movementKind: "native-value" | "erc20-transfer" | "erc721-transfer" | "erc1155-transfer" | "token-transfer-unknown-standard";
  evidenceKind: "observed-runtime-value" | "observed-transfer-log";
  orderDomain: "trace-preorder" | "receipt-log";
  evidenceId: string; runtimeCallId: string | null; logId: string | null;
  mappedContractNodeId: string | null; mappedFunctionNodeId: string | null;
  classificationEvidenceId: string | null; tokenId: string | null; operator: string | null }>;
export type AttemptedAssetFlow = Readonly<{ id: string; transactionHash: string; transactionOrdinal: number;
  assetId: string; from: string; to: string; amount: string; runtimeCallId: string;
  reason: "reverted-transaction" | "reverted-call-or-ancestor" }>;
export type AssetBalanceReconciliation = Readonly<{ observationId: string; assetId: string; participant: string | null;
  kind: "balance" | "ownership" | "total-supply"; before: string | null; after: string | null;
  observedDelta: string | null; ledgerNet: string | null; difference: string | null;
  status: "reconciled" | "partial" | "mismatch" | "insufficient-observation" | "unavailable";
  coverage: "complete-within-observed-set" | "partial" | "insufficient";
  preSnapshotId: string; postSnapshotId: string | null }>;
export type AssetFlow = Readonly<{ schema: typeof ASSET_FLOW_SCHEMA; rulesetVersion: typeof ASSET_ACCOUNTING_RULESET;
  executionId: string; scanId: string; sessionId: string; chainId: number;
  forkIdentity: ImpactOverlay["forkIdentity"];
  capabilities: { assetAccountingAvailable: boolean; traceEvidenceAvailable: boolean;
    stateEvidenceAvailable: boolean; logEvidenceAvailable: boolean };
  status: "complete-within-evidence" | "partial" | "unavailable";
  transactions: Array<{ ordinal: number; hash: string; status: string; traceId: string | null;
    committedEntryIds: string[]; attemptedFlowIds: string[];
    executionCost: { status: "unavailable"; gasUsed: string | null; effectiveGasPrice: null; amountWei: null } }>;
  assets: Array<{ id: string; standard: AssetStandard; contractAddress: string | null;
    tokenId: string | null; mappedContractNodeId: string | null; transactions: number[]; participantCount: number }>;
  participants: Array<{ address: string; label: "Disposable PoC sender" | "Transaction sender" |
    "Mapped protocol contract" | "Zero address" | "Unmapped address"; contractNodeId: string | null }>;
  ledgerEntries: AssetFlowEntry[]; attemptedFlows: AttemptedAssetFlow[];
  netPositions: Array<{ participant: string; assetId: string; incoming: string; outgoing: string;
    netObservedMovement: string }>;
  reconciliation: AssetBalanceReconciliation[];
  summary: { transactionCount: number; committedEntryCount: number; attemptedFlowCount: number;
    assetCount: number; participantCount: number; nativeTransferCount: number; erc20TransferCount: number;
    nftTransferCount: number; erc1155TransferCount: number; reconciledObservationCount: number;
    partialOrMismatchedObservationCount: number };
  warnings: string[];
  provenance: { overlayContentSha256: string; traceIds: string[]; traceContentSha256: string[];
    preSnapshotId: string | null; preSnapshotSha256: string | null; postSnapshotId: string | null;
    postSnapshotSha256: string | null; diffId: string | null; diffSha256: string | null;
    classificationEvidenceIds: string[] };
  contentSha256: string }>;

/** Server-side presentation projection. Canonical ledger identity and order are unchanged. */
export function assetFlowPositionsForTransaction(flow: AssetFlow, ordinal: number): AssetFlow["netPositions"] {
  const positions = new Map<string, { participant: string; assetId: string; incoming: bigint; outgoing: bigint }>();
  for (const entry of flow.ledgerEntries) {
    if (entry.transactionOrdinal !== ordinal) continue;
    for (const [participant, incoming, outgoing] of [
      [entry.from, 0n, BigInt(entry.amount)], [entry.to, BigInt(entry.amount), 0n]
    ] as const) {
      const key = `${participant}:${entry.assetId}`;
      const current = positions.get(key) ?? { participant, assetId: entry.assetId, incoming: 0n, outgoing: 0n };
      current.incoming += incoming; current.outgoing += outgoing; positions.set(key, current);
    }
  }
  return [...positions.values()].sort((a, b) => `${a.assetId}:${a.participant}`.localeCompare(`${b.assetId}:${b.participant}`))
    .map((item) => ({ participant: item.participant, assetId: item.assetId, incoming: item.incoming.toString(),
      outgoing: item.outgoing.toString(), netObservedMovement: (item.incoming - item.outgoing).toString() }));
}

function word(data: string, offset: number): bigint | null {
  const start = 2 + offset * 2;
  return start + 64 <= data.length ? BigInt(`0x${data.slice(start, start + 64)}`) : null;
}
function topicAddress(topic: string | undefined): string | null {
  if (!topic || !/^0x[0-9a-f]{64}$/.test(topic) || !/^0{24}$/.test(topic.slice(2, 26))) return null;
  return `0x${topic.slice(26)}`;
}
function fullData(log: ObservedOverlayLog): string | null {
  return log.data.truncated || (log.data.prefix.length - 2) / 2 !== log.data.byteLength ? null : log.data.prefix;
}
function assetId(chainId: number, standard: AssetStandard, address: string | null, tokenId: string | null): string {
  return standard === "native" ? `native:${chainId}` :
    `${standard}:${chainId}:${address}${tokenId === null ? "" : `:${tokenId}`}`;
}
function effectiveCall(call: ObservedOverlayCall, byId: Map<string, ObservedOverlayCall>): boolean {
  let current: ObservedOverlayCall | undefined = call;
  while (current) {
    if (current.outcome !== "success") return false;
    current = current.parentCallId ? byId.get(current.parentCallId) : undefined;
  }
  return true;
}
function classification(bindings: readonly TrustedAssetStandard[]): Map<string, TrustedAssetStandard> {
  const result = new Map<string, TrustedAssetStandard>();
  for (const item of bindings) {
    const address = item.address.toLowerCase();
    if (!ADDRESS.test(address) || !item.evidenceId || result.has(address))
      throw Error("asset_flow_classification_invalid");
    result.set(address, { ...item, address });
  }
  return result;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

/** Pure, read-only adapter over an exact server-bound Phase 10 overlay. */
export function deriveAssetFlow(overlay: ImpactOverlay, options: { trustedAssetStandards?: readonly TrustedAssetStandard[];
  disposableAccounts?: readonly string[] } = {}): AssetFlow {
  if (overlay.schema !== "contracthunter-impact-overlay-v1") throw Error("asset_flow_overlay_invalid");
  const standards = classification(options.trustedAssetStandards ?? []);
  const disposable = new Set((options.disposableAccounts ?? []).map((address) => address.toLowerCase()));
  if ([...disposable].some((address) => !ADDRESS.test(address))) throw Error("asset_flow_disposable_address_invalid");
  const chain = overlay.forkIdentity.chainId;
  const ledger: AssetFlowEntry[] = [], attempted: AttemptedAssetFlow[] = [], warnings = new Set<string>();
  const callsById = new Map(overlay.observedCalls.map((call) => [call.id, call]));
  const mappedAddresses = new Map<string, string>();
  for (const call of overlay.observedCalls) if (call.to && call.mapping.contractNodeId)
    mappedAddresses.set(call.to, call.mapping.contractNodeId);
  const logsByTx = new Map<string, ObservedOverlayLog[]>();
  for (const log of overlay.observedLogs) {
    const group = logsByTx.get(log.transactionHash) ?? [];
    group.push(log); logsByTx.set(log.transactionHash, group);
  }
  for (const tx of overlay.transactions) {
    for (const call of overlay.observedCalls.filter((item) => item.transactionHash === tx.transactionHash)) {
      if (!["CALL", "CREATE", "CREATE2"].includes(call.callType) || !call.valueWei || BigInt(call.valueWei) === 0n) continue;
      if (!call.to || !ADDRESS.test(call.to)) { warnings.add("native-value-target-unresolved"); continue; }
      const id = `flow:${call.id}`, native = assetId(chain, "native", null, null);
      if (tx.status === "trace-unavailable") { warnings.add("trace-evidence-unavailable"); continue; }
      if (tx.status === "reverted" || !effectiveCall(call, callsById)) {
        attempted.push({ id, transactionHash: tx.transactionHash, transactionOrdinal: tx.ordinal,
          assetId: native, from: call.from, to: call.to, amount: call.valueWei,
          runtimeCallId: call.id, reason: tx.status === "reverted" ? "reverted-transaction" : "reverted-call-or-ancestor" });
      } else ledger.push({ id, transactionHash: tx.transactionHash, transactionOrdinal: tx.ordinal,
        assetId: native, standard: "native", from: call.from, to: call.to, amount: call.valueWei,
        movementKind: "native-value", evidenceKind: "observed-runtime-value", orderDomain: "trace-preorder", evidenceId: call.id,
        runtimeCallId: call.id, logId: null, mappedContractNodeId: call.mapping.contractNodeId,
        mappedFunctionNodeId: call.mapping.functionNodeId, classificationEvidenceId: null, tokenId: null, operator: null });
    }
    if (tx.status !== "success") continue;
    for (const log of logsByTx.get(tx.transactionHash) ?? []) {
      const topic = log.topics[0];
      if (topic !== TRANSFER && topic !== SINGLE && topic !== BATCH) continue;
      const binding = standards.get(log.address);
      const data = fullData(log);
      const from = topic === TRANSFER ? topicAddress(log.topics[1]) : topicAddress(log.topics[2]);
      const to = topic === TRANSFER ? topicAddress(log.topics[2]) : topicAddress(log.topics[3]);
      if (!from || !to || data === null) { warnings.add("transfer-log-unavailable-or-malformed"); continue; }
      const add = (standard: AssetStandard, tokenId: string | null, amount: string, suffix: string, operator: string | null) => {
        ledger.push({ id: `flow:${log.id}${suffix}`, transactionHash: tx.transactionHash, transactionOrdinal: tx.ordinal,
          assetId: assetId(chain, standard, log.address, tokenId), standard, from, to, amount,
          movementKind: standard === "erc20" ? "erc20-transfer" : standard === "erc721" ? "erc721-transfer" :
            standard === "erc1155" ? "erc1155-transfer" : "token-transfer-unknown-standard",
          evidenceKind: "observed-transfer-log", orderDomain: "receipt-log", evidenceId: log.id, runtimeCallId: null, logId: log.id,
          mappedContractNodeId: log.contractNodeId, mappedFunctionNodeId: null,
          classificationEvidenceId: binding?.evidenceId ?? null, tokenId, operator });
      };
      if (topic === TRANSFER) {
        if (binding?.standard === "erc1155") { warnings.add("transfer-standard-conflicts-with-log-shape"); continue; }
        const nftShape = log.topics.length === 4 && log.data.byteLength === 0;
        const fungibleShape = log.topics.length === 3 && log.data.byteLength === 32;
        if (!nftShape && !fungibleShape) { warnings.add("transfer-log-unavailable-or-malformed"); continue; }
        if (binding && (binding.standard === "erc721") !== nftShape) {
          warnings.add("transfer-standard-conflicts-with-log-shape"); continue;
        }
        const tokenId = nftShape ? BigInt(log.topics[3]!).toString() : null;
        const amount = nftShape ? "1" : word(data, 0)!.toString();
        const standard: AssetStandard = binding?.standard === "erc20" ? "erc20" :
          binding?.standard === "erc721" ? "erc721" : "token-unknown-standard";
        if (standard === "token-unknown-standard") warnings.add("token-standard-unresolved");
        add(standard, tokenId, amount, "", null);
      } else {
        if (binding && binding.standard !== "erc1155") { warnings.add("transfer-standard-conflicts-with-log-shape"); continue; }
        const operator = topicAddress(log.topics[1]);
        if (!operator || log.topics.length !== 4) { warnings.add("transfer-log-unavailable-or-malformed"); continue; }
        if (topic === SINGLE) {
          if (log.data.byteLength !== 64) { warnings.add("transfer-log-unavailable-or-malformed"); continue; }
          add("erc1155", word(data, 0)!.toString(), word(data, 32)!.toString(), "", operator);
        } else {
          const idsOffset = word(data, 0), valuesOffset = word(data, 32);
          if (idsOffset === null || valuesOffset === null || idsOffset > 256n || valuesOffset > 256n ||
            idsOffset % 32n !== 0n || valuesOffset % 32n !== 0n) {
            warnings.add("erc1155-batch-malformed-or-oversized"); continue;
          }
          const idsLength = word(data, Number(idsOffset)), valuesLength = word(data, Number(valuesOffset));
          if (idsLength === null || valuesLength === null || idsLength !== valuesLength || idsLength > BigInt(MAX_BATCH) ||
            idsOffset !== 64n || valuesOffset !== 96n + idsLength * 32n ||
            valuesOffset + 32n + valuesLength * 32n !== BigInt(log.data.byteLength)) {
            warnings.add("erc1155-batch-malformed-or-oversized"); continue;
          }
          const entries: Array<[string, string]> = [];
          for (let i = 0; i < Number(idsLength); i++) {
            const id = word(data, Number(idsOffset) + 32 + i * 32), value = word(data, Number(valuesOffset) + 32 + i * 32);
            if (id === null || value === null) break;
            entries.push([id.toString(), value.toString()]);
          }
          if (entries.length !== Number(idsLength)) { warnings.add("erc1155-batch-malformed-or-oversized"); continue; }
          entries.forEach(([id, value], index) => add("erc1155", id, value, `:${index}`, operator));
        }
      }
    }
  }
  const positions = new Map<string, { participant: string; assetId: string; incoming: bigint; outgoing: bigint }>();
  const addPosition = (participant: string, id: string, incoming: bigint, outgoing: bigint) => {
    const key = `${participant}:${id}`, item = positions.get(key) ?? { participant, assetId: id, incoming: 0n, outgoing: 0n };
    item.incoming += incoming; item.outgoing += outgoing; positions.set(key, item);
  };
  for (const item of ledger) {
    addPosition(item.from, item.assetId, 0n, BigInt(item.amount));
    addPosition(item.to, item.assetId, BigInt(item.amount), 0n);
  }
  const netPositions = [...positions.values()].sort((a, b) => `${a.assetId}:${a.participant}`.localeCompare(`${b.assetId}:${b.participant}`))
    .map((item) => ({ participant: item.participant, assetId: item.assetId,
      incoming: item.incoming.toString(), outgoing: item.outgoing.toString(),
      netObservedMovement: (item.incoming - item.outgoing).toString() }));
  const positionMap = new Map(netPositions.map((item) => [`${item.participant}:${item.assetId}`, item]));
  const reconciliation: AssetBalanceReconciliation[] = [];
  for (const state of overlay.observedState) {
    if (!["native", "erc20", "erc721", "erc1155"].includes(state.kind) &&
      !(state.kind === "view" && state.descriptor.kind === "erc20_totalSupply")) continue;
    const address = state.descriptor.address ?? state.descriptor.holder ?? null;
    const token = state.descriptor.token ?? state.descriptor.target ?? null;
    const tokenId = state.descriptor.tokenId ?? null;
    const standard: AssetStandard = state.kind === "view" ? "erc20" : state.kind as AssetStandard;
    const id = assetId(chain, standard, token, ["erc721", "erc1155"].includes(standard) ? tokenId : null);
    const position = address ? positionMap.get(`${address}:${id}`) : null;
    const available = state.beforeStatus === "available" && state.afterStatus === "available";
    const numeric = ["native", "erc20", "erc1155"].includes(state.kind) ||
      state.kind === "view" && state.descriptor.kind === "erc20_totalSupply";
    const observedDelta = available && numeric ? (BigInt(state.after!) - BigInt(state.before!)).toString() : null;
    const ledgerNet = position?.netObservedMovement ?? "0";
    const nativeGasUnknown = state.kind === "native" && overlay.transactions.some((tx) => tx.sender === address);
    let status: AssetBalanceReconciliation["status"] = !available ? "unavailable" : "insufficient-observation";
    if (available && state.kind === "view") status = "insufficient-observation";
    else if (available && state.kind === "erc721") {
      const moves = ledger.filter((item) => item.assetId === id);
      status = !moves.length ? "insufficient-observation" :
        moves[0]!.from === state.before && moves[moves.length - 1]!.to === state.after ? "reconciled" : "mismatch";
    } else if (available && numeric) status = !overlay.capabilities.traceAvailable ? "insufficient-observation" : nativeGasUnknown ? "partial" :
      observedDelta === ledgerNet ? "reconciled" : position ? "mismatch" : "partial";
    const difference = available && numeric && state.kind !== "view" && !nativeGasUnknown ?
      (BigInt(observedDelta!) - BigInt(ledgerNet)).toString() : null;
    if (status === "mismatch") warnings.add("ledger-does-not-reconcile-with-captured-balance");
    if (nativeGasUnknown) warnings.add("native-balance-includes-unpriced-execution-gas");
    reconciliation.push({ observationId: state.observationId, assetId: id, participant: address,
      kind: state.kind === "erc721" ? "ownership" : state.kind === "view" ? "total-supply" : "balance",
      before: state.before, after: state.after, observedDelta, ledgerNet: state.kind === "view" ? null : ledgerNet,
      difference, status, coverage: status === "reconciled" ? "complete-within-observed-set" :
        status === "unavailable" || status === "insufficient-observation" ? "insufficient" : "partial",
      preSnapshotId: state.preSnapshotId, postSnapshotId: state.postSnapshotId });
  }
  const assetMap = new Map<string, AssetFlow["assets"][number]>();
  for (const item of ledger) {
    const current = assetMap.get(item.assetId);
    assetMap.set(item.assetId, { id: item.assetId, standard: item.standard,
      contractAddress: item.standard === "native" ? null : item.assetId.split(":")[2]!, tokenId: item.tokenId,
      mappedContractNodeId: item.mappedContractNodeId,
      transactions: [...new Set([...(current?.transactions ?? []), item.transactionOrdinal])], participantCount: 0 });
  }
  for (const item of attempted) if (!assetMap.has(item.assetId)) assetMap.set(item.assetId, {
    id: item.assetId, standard: "native", contractAddress: null, tokenId: null,
    mappedContractNodeId: null, transactions: [item.transactionOrdinal], participantCount: 0 });
  for (const state of reconciliation) if (!assetMap.has(state.assetId)) assetMap.set(state.assetId, {
    id: state.assetId, standard: state.assetId.split(":")[0] as AssetStandard,
    contractAddress: state.assetId.startsWith("native:") ? null : state.assetId.split(":")[2]!,
    tokenId: state.assetId.split(":")[3] ?? null, mappedContractNodeId: null, transactions: [], participantCount: 0 });
  const assets = [...assetMap.values()].sort((a, b) => a.id.localeCompare(b.id)).map((item) => ({ ...item,
    participantCount: new Set([...netPositions.filter((position) => position.assetId === item.id).map((position) => position.participant),
      ...attempted.filter((flow) => flow.assetId === item.id).flatMap((flow) => [flow.from, flow.to]),
      ...reconciliation.filter((observation) => observation.assetId === item.id && observation.participant)
        .map((observation) => observation.participant!)]).size }));
  const participantAddresses = new Set([...ledger.flatMap((item) => [item.from, item.to]),
    ...attempted.flatMap((item) => [item.from, item.to]),
    ...reconciliation.flatMap((item) => item.participant ? [item.participant] : [])]);
  const participants = [...participantAddresses].sort().map((address) => ({ address,
    label: address === ZERO ? "Zero address" as const : disposable.has(address) ? "Disposable PoC sender" as const :
      mappedAddresses.has(address) ? "Mapped protocol contract" as const :
        overlay.transactions.some((tx) => tx.sender === address) ? "Transaction sender" as const : "Unmapped address" as const,
    contractNodeId: mappedAddresses.get(address) ?? null }));
  const transactions = overlay.transactions.map((tx) => ({ ordinal: tx.ordinal, hash: tx.transactionHash,
    status: tx.status, traceId: tx.receiptTraceId,
    committedEntryIds: ledger.filter((item) => item.transactionHash === tx.transactionHash).map((item) => item.id),
    attemptedFlowIds: attempted.filter((item) => item.transactionHash === tx.transactionHash).map((item) => item.id),
    executionCost: { status: "unavailable" as const, gasUsed: tx.gasUsed, effectiveGasPrice: null, amountWei: null } }));
  if (overlay.transactions.some((tx) => tx.gasUsed !== null)) warnings.add("effective-gas-price-not-persisted");
  if (!overlay.capabilities.traceAvailable) warnings.add("trace-evidence-unavailable");
  if (!overlay.capabilities.stateDiffAvailable) warnings.add("state-diff-unavailable");
  if (overlay.observedCalls.some((call) => call.callType === "SELFDESTRUCT")) warnings.add("selfdestruct-beneficiary-semantics-unavailable");
  const summary = { transactionCount: transactions.length, committedEntryCount: ledger.length,
    attemptedFlowCount: attempted.length, assetCount: assets.length, participantCount: participants.length,
    nativeTransferCount: ledger.filter((item) => item.standard === "native").length,
    erc20TransferCount: ledger.filter((item) => item.standard === "erc20").length,
    nftTransferCount: ledger.filter((item) => item.standard === "erc721").length,
    erc1155TransferCount: ledger.filter((item) => item.standard === "erc1155").length,
    reconciledObservationCount: reconciliation.filter((item) => item.status === "reconciled").length,
    partialOrMismatchedObservationCount: reconciliation.filter((item) => ["partial", "mismatch"].includes(item.status)).length };
  const provenance = { overlayContentSha256: overlay.contentSha256,
    traceIds: overlay.provenance.traceIds, traceContentSha256: overlay.provenance.traceContentSha256,
    preSnapshotId: overlay.provenance.preSnapshotId, preSnapshotSha256: overlay.provenance.preSnapshotSha256,
    postSnapshotId: overlay.provenance.postSnapshotId, postSnapshotSha256: overlay.provenance.postSnapshotSha256,
    diffId: overlay.provenance.diffId, diffSha256: overlay.provenance.diffSha256,
    classificationEvidenceIds: [...standards.values()].map((item) => item.evidenceId).sort() };
  const status = !overlay.capabilities.traceAvailable && !overlay.capabilities.statePreAvailable ? "unavailable" as const :
    overlay.capabilities.traceAvailable && overlay.capabilities.stateDiffAvailable && warnings.size === 0 ?
      "complete-within-evidence" as const : "partial" as const;
  const content = { schema: ASSET_FLOW_SCHEMA, rulesetVersion: ASSET_ACCOUNTING_RULESET,
    executionId: overlay.executionId, scanId: overlay.scanId, sessionId: overlay.sessionId, chainId: chain,
    forkIdentity: overlay.forkIdentity,
    capabilities: { assetAccountingAvailable: status !== "unavailable", traceEvidenceAvailable: overlay.capabilities.traceAvailable,
      stateEvidenceAvailable: overlay.capabilities.statePreAvailable,
      logEvidenceAvailable: overlay.transactions.some((tx) => tx.traceAvailable) },
    status, transactions, assets, participants, ledgerEntries: ledger, attemptedFlows: attempted,
    netPositions, reconciliation, summary, warnings: [...warnings].sort(), provenance };
  return { ...content, contentSha256: canonicalImpactHash(ASSET_FLOW_SCHEMA,
    [ASSET_ACCOUNTING_RULESET, overlay.contentSha256, canonical(content)]) };
}
