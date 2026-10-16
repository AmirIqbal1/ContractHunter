import { createHash } from "node:crypto";
import { z } from "zod";
import { protocolSourceLocationSchema, type ProtocolGraphEdge, type ProtocolGraphNode } from "./protocol-graph";
import type { StaticProtocolGraphArtifact } from "./static-protocol-graph";

export const FUNCTION_EXPLORER_SCHEMA = "contracthunter-function-explorer-v1" as const;
export const FUNCTION_EXPLORER_LIMITS = { operations: 512, relationships: 512, stateRefs: 256,
  findings: 128, modifiers: 32, warnings: 16, previewBytes: 4096 } as const;
export const functionOperationKinds = ["modifier", "condition", "revert", "state-read", "state-write",
  "internal-call", "external-call", "low-level-call", "delegatecall", "staticcall",
  "token-transfer-like", "native-transfer", "event-emission", "return", "assembly",
  "callback-like", "branch", "loop", "try-catch", "unknown"] as const;
export const functionReviewCues = ["externally-callable", "state-changing", "state-write-before-external-call-source-order",
  "state-write-after-external-call-source-order", "delegatecall-present", "unresolved-external-call",
  "token-transfer", "native-value-transfer", "privileged", "payable", "assembly-present", "finding-linked"] as const;
const nodeId = z.string().regex(/^pn:[a-f0-9]{64}$/), edgeId = z.string().regex(/^pe:[a-f0-9]{64}$/);
const operationSchema = z.object({ id: z.string().regex(/^fo:[a-f0-9]{64}$/), kind: z.enum(functionOperationKinds),
  identityKey: z.string().min(1).max(128),
  source: protocolSourceLocationSchema, ordinal: z.number().int().nonnegative(),
  detail: z.string().max(160).nullable(), detailSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
  detailTruncated: z.boolean(), targetFunctionId: nodeId.nullable(), targetContractId: nodeId.nullable(),
  resolution: z.enum(["resolved", "unresolved", "not-applicable"]),
  origin: z.enum(["compiler-ast", "static-graph"]) }).strict();
const relationshipSchema = z.object({ edgeId, kind: z.enum(["calls", "external-call", "delegates", "controls"]),
  fromFunctionId: nodeId.nullable(), toFunctionId: nodeId.nullable(), source: protocolSourceLocationSchema,
  targetStatus: z.enum(["resolved", "unresolved"]), evidenceOrigins: z.array(z.string().max(80)).max(8) }).strict();
const stateRefSchema = z.object({ variable: z.string().max(200), contractId: nodeId,
  declarationId: z.number().int().nonnegative(), source: protocolSourceLocationSchema }).strict();
const modifierSchema = z.object({ name: z.string().max(200), declarationId: z.number().int().nonnegative().nullable(),
  source: protocolSourceLocationSchema.nullable() }).strict();
const modelShape = z.object({ schema: z.literal(FUNCTION_EXPLORER_SCHEMA), scanId: z.string().uuid(),
  graphId: z.string().regex(/^pg:[a-f0-9]{64}$/), contractId: nodeId, functionId: nodeId,
  contract: z.object({ name: z.string().max(200), kind: z.enum(["contract", "interface", "library"]),
    source: protocolSourceLocationSchema }).strict(),
  function: z.object({ name: z.string().max(200), signature: z.string().max(256),
    visibility: z.enum(["public", "external", "internal", "private", "unknown"]),
    mutability: z.enum(["pure", "view", "nonpayable", "payable", "unknown"]),
    entryPoint: z.enum(["yes", "no", "unknown"]), source: protocolSourceLocationSchema }).strict(),
  analysisStatus: z.enum(["complete", "partial", "unavailable"]), sourceOrderOnly: z.literal(true),
  cfgStatus: z.literal("unavailable"), modifiers: z.array(modifierSchema).max(FUNCTION_EXPLORER_LIMITS.modifiers),
  operations: z.array(operationSchema).max(FUNCTION_EXPLORER_LIMITS.operations),
  callers: z.array(relationshipSchema).max(FUNCTION_EXPLORER_LIMITS.relationships),
  callees: z.array(relationshipSchema).max(FUNCTION_EXPLORER_LIMITS.relationships),
  controls: z.array(relationshipSchema).max(FUNCTION_EXPLORER_LIMITS.relationships),
  stateReads: z.array(stateRefSchema).max(FUNCTION_EXPLORER_LIMITS.stateRefs),
  stateWrites: z.array(stateRefSchema).max(FUNCTION_EXPLORER_LIMITS.stateRefs),
  findings: z.array(z.string().uuid()).max(FUNCTION_EXPLORER_LIMITS.findings),
  reviewCues: z.array(z.enum(functionReviewCues)).max(functionReviewCues.length),
  summary: z.object({ modifiers: z.number().int().nonnegative(), conditions: z.number().int().nonnegative(),
    stateReads: z.number().int().nonnegative(), stateWrites: z.number().int().nonnegative(),
    internalCalls: z.number().int().nonnegative(), externalCalls: z.number().int().nonnegative(),
    unresolvedCalls: z.number().int().nonnegative(), lowLevelCalls: z.number().int().nonnegative(),
    delegatecalls: z.number().int().nonnegative(), tokenTransfers: z.number().int().nonnegative(),
    nativeTransfers: z.number().int().nonnegative(), eventEmissions: z.number().int().nonnegative(),
    findings: z.number().int().nonnegative() }).strict(),
  provenance: z.array(z.object({ origin: z.string().max(80), version: z.string().max(80) }).strict()).max(16),
  warnings: z.array(z.enum(["syntax-facts-unavailable", "syntax-facts-truncated", "operation-limit-reached",
    "relationships-truncated", "state-access-sites-collapsed", "unresolved-call-target", "source-order-only"])).max(FUNCTION_EXPLORER_LIMITS.warnings),
  contentSha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
export type FunctionExplorerModel = z.infer<typeof modelShape>;
export type FunctionOperation = FunctionExplorerModel["operations"][number];
export type FunctionOverlayReference = { functionId: string; operationId: string | null;
  kind: "impact-trace" | "impact-state"; executionId: string; artifactId: string };
export function validateFunctionOverlayReferences(model: FunctionExplorerModel, refs: readonly FunctionOverlayReference[]): void {
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
  if (refs.length > 1_000 || refs.some((ref) => ref.functionId !== model.functionId ||
    !["impact-trace", "impact-state"].includes(ref.kind) || !uuid.test(ref.executionId) || !uuid.test(ref.artifactId) ||
    ref.operationId !== null && !model.operations.some((operation) => operation.id === ref.operationId)))
    throw Error("function_overlay_reference_invalid");
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const digest = (domain: string, value: unknown) => createHash("sha256").update(domain).update("\0").update(canonical(value)).digest("hex");
export function functionOperationId(functionId: string, kind: FunctionOperation["kind"],
  source: FunctionOperation["source"], discriminator: string): string {
  return `fo:${digest("contracthunter-function-operation-v1", [functionId, kind, source.sourceUnitName,
    source.startByte, source.endByte, source.startLine, source.startColumn, discriminator])}`;
}
export function functionExplorerHash(model: Omit<FunctionExplorerModel, "contentSha256">): string {
  return digest(FUNCTION_EXPLORER_SCHEMA, model);
}
export function validateFunctionExplorerModel(input: unknown): FunctionExplorerModel {
  const model = modelShape.parse(input);
  const { contentSha256, ...content } = model;
  if (contentSha256 !== functionExplorerHash(content) ||
    model.operations.some((operation, index) => operation.ordinal !== index ||
      operation.source.sourceUnitName !== model.function.source.sourceUnitName ||
      operation.id !== functionOperationId(model.functionId, operation.kind, operation.source, operation.identityKey)) ||
    new Set(model.operations.map((operation) => operation.id)).size !== model.operations.length ||
    new Set(model.findings).size !== model.findings.length ||
    new Set(model.reviewCues).size !== model.reviewCues.length) throw Error("function_explorer_integrity_invalid");
  return model;
}

function owner(node: ProtocolGraphNode | undefined): string | null {
  return node?.kind === "function" ? node.contractId : node?.id ?? null;
}
function graphCall(edge: ProtocolGraphEdge): boolean {
  return ["calls", "external-call", "delegates"].includes(edge.kind);
}
export function buildFunctionExplorerModel(artifact: StaticProtocolGraphArtifact, contractId: string,
  functionId: string): FunctionExplorerModel | null {
  const graph = artifact.graph, byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const contract = byId.get(contractId), fn = byId.get(functionId);
  if (!contract || !["contract", "interface", "library"].includes(contract.kind) || !contract.source ||
    fn?.kind !== "function" || fn.contractId !== contractId || !fn.source) return null;
  const facts = artifact.functionFacts.find((item) => item.functionId === functionId);
  const syntax = artifact.functionSyntax?.find((item) => item.functionId === functionId);
  const outbound = graph.edges.filter((edge) => graphCall(edge) &&
    (edge.from === functionId || edge.fromFunctionId === functionId));
  const inbound = graph.edges.filter((edge) => graphCall(edge) &&
    (edge.to === functionId || edge.toFunctionId === functionId));
  const controlEdges = graph.edges.filter((edge) => edge.kind === "controls" &&
    (edge.to === functionId || edge.toFunctionId === functionId));
  const warnings = new Set<FunctionExplorerModel["warnings"][number]>(["source-order-only"]);
  if (!syntax) warnings.add("syntax-facts-unavailable");
  if (syntax?.truncated) warnings.add("syntax-facts-truncated");
  if ((facts?.stateReads.length ?? 0) || (facts?.stateWrites.length ?? 0)) warnings.add("state-access-sites-collapsed");
  const unresolved = artifact.unresolved.filter((item) => item.callerFunctionId === functionId);
  if (unresolved.length) warnings.add("unresolved-call-target");
  const pending: Array<Omit<FunctionOperation, "id" | "ordinal" | "identityKey"> & { discriminator: string }> = [];
  const add = (item: Omit<FunctionOperation, "id" | "ordinal" | "identityKey">, discriminator: string) => {
    if (pending.length >= FUNCTION_EXPLORER_LIMITS.operations * 4) { warnings.add("operation-limit-reached"); return; }
    pending.push({ ...item, discriminator });
  };
  for (const seed of syntax?.operations ?? []) add({ kind: seed.kind, source: seed.source,
    detail: seed.excerpt ?? seed.label, detailSha256: seed.expressionSha256,
    detailTruncated: seed.excerptTruncated, targetFunctionId: null, targetContractId: null,
    resolution: "not-applicable", origin: "compiler-ast" }, `syntax:${seed.astNodeId}`);
  const modifiers = (facts?.modifierInvocations.length ? facts.modifierInvocations.map((item) =>
    ({ name: item.name, declarationId: item.declarationId, source: item.source })) :
    fn.modifiers.map((name) => ({ name, declarationId: null, source: null })))
    .slice(0, FUNCTION_EXPLORER_LIMITS.modifiers);
  for (const [index, modifier] of modifiers.entries()) if (modifier.source) add({ kind: "modifier", source: modifier.source,
    detail: modifier.name, detailSha256: null, detailTruncated: false, targetFunctionId: null,
    targetContractId: null, resolution: modifier.declarationId === null ? "unresolved" : "resolved",
    origin: "compiler-ast" }, `modifier:${modifier.declarationId ?? index}`);
  for (const [kind, refs] of [["state-read", facts?.stateReads ?? []], ["state-write", facts?.stateWrites ?? []]] as const)
    for (const ref of refs) add({ kind, source: ref.source, detail: ref.variable, detailSha256: null,
      detailTruncated: false, targetFunctionId: null, targetContractId: ref.contractId,
      resolution: "resolved", origin: "static-graph" }, `state:${ref.contractId}:${ref.declarationId}`);
  // Phase 3 emits both calls and external-call edges for a resolved typed member call.
  const callSite = new Map<string, ProtocolGraphEdge>();
  for (const edge of outbound.filter((item) => item.kind !== "controls" && item.source)) {
    const key = `${edge.source!.sourceUnitName}:${edge.source!.startByte ?? edge.source!.startLine}:${edge.toFunctionId ?? edge.to}`;
    const prior = callSite.get(key);
    if (!prior || edge.kind === "external-call" && prior.kind === "calls") callSite.set(key, edge);
  }
  for (const edge of callSite.values()) {
    const to = byId.get(edge.toFunctionId ?? edge.to), reason = edge.reasons[0] ?? "";
    const low = reason.startsWith("low-level-") ? reason.slice("low-level-".length) : null;
    const kind: FunctionOperation["kind"] = low === "delegatecall" || edge.kind === "delegates" ? "delegatecall" :
      low === "staticcall" ? "staticcall" : low ? "low-level-call" :
      edge.kind === "external-call" || owner(to) !== contractId ? "external-call" : "internal-call";
    const resolved = to?.kind === "function";
    add({ kind, source: edge.source!, detail: low ?? (to?.kind === "function" ? to.signature : null),
      detailSha256: null, detailTruncated: false, targetFunctionId: resolved ? to.id : null,
      targetContractId: resolved ? to.contractId : to && ["contract", "interface", "library"].includes(to.kind) ? to.id : null,
      resolution: resolved || to && ["contract", "interface", "library"].includes(to.kind) ? "resolved" : "unresolved",
      origin: "static-graph" }, `edge:${edge.id}`);
  }
  for (const item of unresolved) if (!pending.some((operation) => operation.source.startByte === item.source.startByte &&
    ["internal-call", "external-call", "low-level-call", "delegatecall", "staticcall"].includes(operation.kind)))
    add({ kind: item.kind === "internal-call" ? "internal-call" : "external-call", source: item.source,
      detail: item.expression, detailSha256: null, detailTruncated: false, targetFunctionId: null,
      targetContractId: null, resolution: "unresolved", origin: "static-graph" },
    `unresolved:${item.kind}:${item.reason}:${item.source.startByte ?? item.source.startLine}`);
  for (const trait of fn.characteristics.filter((item) => ["token-transfer", "native-transfer"].includes(item.kind)))
    for (const [index, evidence] of trait.evidence.entries()) if (evidence.source) add({
      kind: trait.kind === "token-transfer" ? "token-transfer-like" : "native-transfer",
      source: evidence.source, detail: null, detailSha256: null, detailTruncated: false,
      targetFunctionId: null, targetContractId: null, resolution: "unresolved", origin: "static-graph",
    }, `trait:${trait.kind}:${evidence.referenceId ?? index}`);
  pending.sort((a, b) => (a.source.startByte ?? Number.MAX_SAFE_INTEGER) -
    (b.source.startByte ?? Number.MAX_SAFE_INTEGER) || a.source.startLine - b.source.startLine ||
    a.kind.localeCompare(b.kind) || a.discriminator.localeCompare(b.discriminator));
  if (pending.length > FUNCTION_EXPLORER_LIMITS.operations) warnings.add("operation-limit-reached");
  const operations = pending.slice(0, FUNCTION_EXPLORER_LIMITS.operations)
    .map(({ discriminator, ...item }, ordinal) => ({ ...item, ordinal, identityKey: discriminator,
      id: functionOperationId(functionId, item.kind, item.source, discriminator) }));
  const relationship = (edge: ProtocolGraphEdge): FunctionExplorerModel["callees"][number] | null => {
    if (!edge.source) return null;
    const target = byId.get(edge.toFunctionId ?? edge.to);
    return { edgeId: edge.id, kind: edge.kind as "calls" | "external-call" | "delegates" | "controls",
      fromFunctionId: edge.fromFunctionId ?? (byId.get(edge.from)?.kind === "function" ? edge.from : null),
      toFunctionId: edge.toFunctionId ?? (target?.kind === "function" ? target.id : null),
      source: edge.source, targetStatus: target?.kind === "external-actor" || !target ? "unresolved" : "resolved",
      evidenceOrigins: [...new Set(edge.evidence.map((item) => item.origin))].sort() };
  };
  if (outbound.length > FUNCTION_EXPLORER_LIMITS.relationships || inbound.length > FUNCTION_EXPLORER_LIMITS.relationships ||
    controlEdges.length > FUNCTION_EXPLORER_LIMITS.relationships)
    warnings.add("relationships-truncated");
  const callees = outbound.slice(0, FUNCTION_EXPLORER_LIMITS.relationships).map(relationship)
    .filter((item): item is NonNullable<typeof item> => !!item).sort((a, b) => a.edgeId.localeCompare(b.edgeId));
  const callers = inbound.slice(0, FUNCTION_EXPLORER_LIMITS.relationships).map(relationship)
    .filter((item): item is NonNullable<typeof item> => !!item).sort((a, b) => a.edgeId.localeCompare(b.edgeId));
  const controls = controlEdges.slice(0, FUNCTION_EXPLORER_LIMITS.relationships).map(relationship)
    .filter((item): item is NonNullable<typeof item> => !!item).sort((a, b) => a.edgeId.localeCompare(b.edgeId));
  const findings = [...new Set(artifact.findingLinks.filter((item) => item.nodeId === functionId)
    .map((item) => item.findingId))].sort().slice(0, FUNCTION_EXPLORER_LIMITS.findings);
  const counts = (kind: FunctionOperation["kind"]) => operations.filter((item) => item.kind === kind).length;
  const external = operations.filter((item) => ["external-call", "low-level-call", "delegatecall", "staticcall"].includes(item.kind));
  const writes = operations.filter((item) => item.kind === "state-write");
  const cues = new Set<FunctionExplorerModel["reviewCues"][number]>();
  if (fn.entryPoint === "yes") cues.add("externally-callable");
  if (writes.length) cues.add("state-changing");
  if (writes.some((write) => external.some((call) => (write.source.startByte ?? -1) < (call.source.startByte ?? -1) &&
    write.source.startByte !== null && call.source.startByte !== null))) cues.add("state-write-before-external-call-source-order");
  if (writes.some((write) => external.some((call) => (write.source.startByte ?? -1) > (call.source.startByte ?? -1) &&
    write.source.startByte !== null && call.source.startByte !== null))) cues.add("state-write-after-external-call-source-order");
  if (counts("delegatecall")) cues.add("delegatecall-present");
  if (external.some((item) => item.resolution === "unresolved")) cues.add("unresolved-external-call");
  if (counts("token-transfer-like")) cues.add("token-transfer");
  if (counts("native-transfer")) cues.add("native-value-transfer");
  if (controls.length) cues.add("privileged");
  if (fn.mutability === "payable") cues.add("payable");
  if (counts("assembly")) cues.add("assembly-present");
  if (findings.length) cues.add("finding-linked");
  const content: Omit<FunctionExplorerModel, "contentSha256"> = { schema: FUNCTION_EXPLORER_SCHEMA,
    scanId: graph.scanId, graphId: graph.id, contractId, functionId,
    contract: { name: contract.name, kind: contract.kind as "contract" | "interface" | "library", source: contract.source },
    function: { name: fn.name, signature: fn.signature, visibility: fn.visibility,
      mutability: fn.mutability, entryPoint: fn.entryPoint, source: fn.source },
    analysisStatus: !syntax || syntax.truncated || warnings.has("operation-limit-reached") ||
      warnings.has("relationships-truncated") || warnings.has("state-access-sites-collapsed") ? "partial" : "complete",
    sourceOrderOnly: true, cfgStatus: "unavailable", modifiers, operations, callers, callees, controls,
    stateReads: (facts?.stateReads ?? []).slice(0, FUNCTION_EXPLORER_LIMITS.stateRefs),
    stateWrites: (facts?.stateWrites ?? []).slice(0, FUNCTION_EXPLORER_LIMITS.stateRefs), findings,
    reviewCues: [...cues].sort(), summary: { modifiers: modifiers.length, conditions: counts("condition"),
      stateReads: (facts?.stateReads ?? []).length, stateWrites: (facts?.stateWrites ?? []).length,
      internalCalls: counts("internal-call"), externalCalls: counts("external-call"),
      unresolvedCalls: external.filter((item) => item.resolution === "unresolved").length,
      lowLevelCalls: counts("low-level-call") + counts("staticcall") + counts("delegatecall"),
      delegatecalls: counts("delegatecall"), tokenTransfers: counts("token-transfer-like"),
      nativeTransfers: counts("native-transfer"), eventEmissions: counts("event-emission"), findings: findings.length },
    provenance: [...new Map([...fn.evidence, ...outbound.flatMap((item) => item.evidence)].map((item) =>
      [`${item.origin}:${item.producerVersion}`, { origin: item.origin, version: item.producerVersion }])).values()]
      .sort((a, b) => a.origin.localeCompare(b.origin) || a.version.localeCompare(b.version)).slice(0, 16),
    warnings: [...warnings].sort() };
  return validateFunctionExplorerModel({ ...content, contentSha256: functionExplorerHash(content) });
}
