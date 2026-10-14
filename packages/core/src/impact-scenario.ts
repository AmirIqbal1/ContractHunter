import { z } from "zod";
import { canonicalImpactHash } from "./impact-state";
import type { AssetFlow, AssetFlowEntry } from "./asset-flow";

export const IMPACT_SCENARIO_SCHEMA = "contracthunter-impact-scenario-v1" as const;
export const SCENARIO_IMPACT_SCHEMA = "contracthunter-scenario-impact-v1" as const;
export const SCENARIO_IMPACT_DERIVATION = "contracthunter-scenario-impact-deriver-v1" as const;
export const SCENARIO_IMPACT_RULESET = "contracthunter-scenario-impact-ruleset-v1" as const;
export const scenarioRoles = ["scenario-subject", "protocol", "counterparty", "unassigned"] as const;
export type ScenarioRole = typeof scenarioRoles[number];
export type ScenarioAssignment = Readonly<{ participantId: string; role: ScenarioRole }>;
const participantIdSchema = z.string().regex(/^sp:sha256:[0-9a-f]{64}$/);
export const scenarioAssignmentInputSchema = z.object({ participantId: participantIdSchema,
  role: z.enum(scenarioRoles) }).strict();
export const scenarioDraftInputSchema = z.object({ assignments: z.array(scenarioAssignmentInputSchema).max(512),
  note: z.string().max(1000).default("") }).strict();

export type ImpactScenario = Readonly<{ schema: typeof IMPACT_SCENARIO_SCHEMA; id: string; scenarioId: string;
  revision: number; revisionOf: string | null; scanId: string; executionId: string;
  subject: { type: "finding" | "hypothesis"; id: string }; assetFlowContentSha256: string;
  assetAccountingRulesetVersion: string; status: "draft" | "reviewed" | "rejected";
  assignments: ScenarioAssignment[]; note: string; createdAt: number; reviewedAt: number | null;
  rejectedAt: number | null; contentSha256: string }>;
export type ScenarioPosition = Readonly<{ transactionOrdinal: number | null; role: ScenarioRole;
  assetId: string; incoming: string; outgoing: string; netObservedMovement: string; ledgerEntryIds: string[] }>;
export type DirectRoleTransfer = Readonly<{ transactionOrdinal: number | null; assetId: string;
  direction: "protocol-to-subject" | "subject-to-protocol"; amount: string; ledgerEntryIds: string[] }>;
export type ScenarioImpact = Readonly<{ schema: typeof SCENARIO_IMPACT_SCHEMA;
  derivationVersion: typeof SCENARIO_IMPACT_DERIVATION; rulesetVersion: typeof SCENARIO_IMPACT_RULESET;
  scenarioId: string; revisionId: string; revision: number; scanId: string; executionId: string;
  assetFlowContentSha256: string; assetAccountingRulesetVersion: string; preview: boolean;
  status: AssetFlow["status"]; roles: Array<ScenarioAssignment & { address: string }>;
  rolePositions: ScenarioPosition[]; directRoleTransfers: DirectRoleTransfer[];
  supplyObservations: AssetFlow["reconciliation"]; reconciliation: AssetFlow["reconciliation"];
  executionCosts: AssetFlow["transactions"][number]["executionCost"][];
  attemptedFlowIds: string[]; warnings: string[]; contentSha256: string }>;

/** Opaque selector for one participant in one exact E1 result. */
export function scenarioParticipantId(flow: AssetFlow, address: string): string {
  return `sp:${canonicalImpactHash("scenario-participant-v1", [flow.contentSha256, address])}`;
}
export function validateScenarioAssignments(flow: AssetFlow, input: readonly ScenarioAssignment[]): ScenarioAssignment[] {
  const parsed = z.array(scenarioAssignmentInputSchema).max(512).parse(input);
  const byId = new Map(flow.participants.map((item) => [scenarioParticipantId(flow, item.address), item]));
  const seen = new Set<string>();
  for (const item of parsed) {
    const participant = byId.get(item.participantId);
    if (!participant || seen.has(item.participantId)) throw Error("scenario_role_collision_or_unknown_participant");
    if (participant.label === "Zero address" && item.role !== "unassigned") throw Error("scenario_zero_address_role_invalid");
    seen.add(item.participantId);
  }
  return [...parsed].sort((a, b) => a.participantId.localeCompare(b.participantId));
}
export function scenarioContentHash(input: Pick<ImpactScenario, "scenarioId" | "revision" | "revisionOf" |
  "scanId" | "executionId" | "subject" | "assetFlowContentSha256" | "assetAccountingRulesetVersion" |
  "assignments" | "note">): string {
  return canonicalImpactHash(IMPACT_SCENARIO_SCHEMA, [input.scenarioId, input.revision, input.revisionOf,
    input.scanId, input.executionId, input.subject.type, input.subject.id, input.assetFlowContentSha256,
    input.assetAccountingRulesetVersion, [...input.assignments].sort((a, b) => a.participantId.localeCompare(b.participantId)), input.note]);
}

/** Exact, per-asset accounting over committed E1 entries and explicit reviewed roles. */
export function deriveScenarioImpact(flow: AssetFlow, scenario: ImpactScenario,
  options: { preview?: boolean } = {}): ScenarioImpact {
  const preview = options.preview === true;
  if (scenario.scanId !== flow.scanId || scenario.executionId !== flow.executionId ||
    scenario.assetFlowContentSha256 !== flow.contentSha256 ||
    scenario.assetAccountingRulesetVersion !== flow.rulesetVersion) throw Error("scenario_asset_flow_stale");
  if (scenario.status !== (preview ? "draft" : "reviewed")) throw Error("scenario_not_reviewed");
  const assignments = validateScenarioAssignments(flow, scenario.assignments);
  if (scenario.contentSha256 !== scenarioContentHash({ ...scenario, assignments })) throw Error("scenario_content_invalid");
  const participants = new Map(flow.participants.map((item) => [scenarioParticipantId(flow, item.address), item.address]));
  const roles = assignments.map((item) => ({ ...item, address: participants.get(item.participantId)! }));
  const roleByAddress = new Map(roles.map((item) => [item.address, item.role]));
  const roleOf = (address: string): ScenarioRole => roleByAddress.get(address) ?? "unassigned";
  type PositionValue = { transactionOrdinal: number | null; role: ScenarioRole; assetId: string;
    incoming: bigint; outgoing: bigint; ids: string[] };
  type TransferValue = { transactionOrdinal: number | null; assetId: string;
    direction: DirectRoleTransfer["direction"]; amount: bigint; ids: string[] };
  const positions = new Map<string, PositionValue>(), transfers = new Map<string, TransferValue>();
  const updatePosition = (entry: AssetFlowEntry, role: ScenarioRole,
    ordinal: number | null, incoming: bigint, outgoing: bigint) => {
    const key = `${ordinal ?? "all"}|${role}|${entry.assetId}`;
    const p = positions.get(key) ?? { transactionOrdinal: ordinal, role, assetId: entry.assetId,
      incoming: 0n, outgoing: 0n, ids: [] };
    p.incoming += incoming; p.outgoing += outgoing; p.ids.push(entry.id); positions.set(key, p);
  };
  const updateTransfer = (entry: AssetFlowEntry, ordinal: number | null,
    direction: DirectRoleTransfer["direction"], amount: bigint) => {
    const key = `${ordinal ?? "all"}|${entry.assetId}|${direction}`;
    const t = transfers.get(key) ?? { transactionOrdinal: ordinal, assetId: entry.assetId,
      direction, amount: 0n, ids: [] };
    t.amount += amount; if (amount > 0n) t.ids.push(entry.id); transfers.set(key, t);
  };
  let unassignedFlow = false;
  for (const entry of flow.ledgerEntries) {
    const fromRole = roleOf(entry.from), toRole = roleOf(entry.to), amount = BigInt(entry.amount);
    if (amount > 0n && (fromRole === "unassigned" || toRole === "unassigned")) unassignedFlow = true;
    for (const ordinal of [null, entry.transactionOrdinal]) {
      updatePosition(entry, fromRole, ordinal, 0n, amount);
      updatePosition(entry, toRole, ordinal, amount, 0n);
      updateTransfer(entry, ordinal, "protocol-to-subject", 0n);
      updateTransfer(entry, ordinal, "subject-to-protocol", 0n);
      if (fromRole === "protocol" && toRole === "scenario-subject")
        updateTransfer(entry, ordinal, "protocol-to-subject", amount);
      else if (fromRole === "scenario-subject" && toRole === "protocol")
        updateTransfer(entry, ordinal, "subject-to-protocol", amount);
    }
  }
  const ordinal = (a: number | null, b: number | null) => (a ?? -1) - (b ?? -1);
  const rolePositions = [...positions.values()].sort((a, b) => ordinal(a.transactionOrdinal, b.transactionOrdinal) ||
    a.assetId.localeCompare(b.assetId) || a.role.localeCompare(b.role)).map((item) => ({
    transactionOrdinal: item.transactionOrdinal, role: item.role, assetId: item.assetId,
    incoming: item.incoming.toString(), outgoing: item.outgoing.toString(),
    netObservedMovement: (item.incoming - item.outgoing).toString(), ledgerEntryIds: [...new Set(item.ids)] }));
  const directRoleTransfers = [...transfers.values()].sort((a, b) => ordinal(a.transactionOrdinal, b.transactionOrdinal) ||
    a.assetId.localeCompare(b.assetId) || a.direction.localeCompare(b.direction)).map((item) => ({
    transactionOrdinal: item.transactionOrdinal, assetId: item.assetId, direction: item.direction,
    amount: item.amount.toString(), ledgerEntryIds: item.ids }));
  const warnings = [...new Set([...flow.warnings, ...(unassignedFlow ? ["unassigned-participant-flow"] : [])])].sort();
  const content = { schema: SCENARIO_IMPACT_SCHEMA, derivationVersion: SCENARIO_IMPACT_DERIVATION,
    rulesetVersion: SCENARIO_IMPACT_RULESET, scenarioId: scenario.scenarioId, revisionId: scenario.id,
    revision: scenario.revision, scanId: scenario.scanId, executionId: scenario.executionId,
    assetFlowContentSha256: flow.contentSha256, assetAccountingRulesetVersion: flow.rulesetVersion,
    preview, status: flow.status, roles, rolePositions, directRoleTransfers,
    supplyObservations: flow.reconciliation.filter((item) => item.kind === "total-supply"),
    reconciliation: flow.reconciliation, executionCosts: flow.transactions.map((item) => item.executionCost),
    attemptedFlowIds: flow.attemptedFlows.map((item) => item.id), warnings };
  return { ...content, contentSha256: canonicalImpactHash(SCENARIO_IMPACT_SCHEMA,
    [SCENARIO_IMPACT_DERIVATION, SCENARIO_IMPACT_RULESET, scenario.contentSha256, flow.contentSha256, content]) };
}
