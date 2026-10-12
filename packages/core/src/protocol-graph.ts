import { createHash } from "node:crypto";
import { z } from "zod";
import { repositorySolidityPathSchema } from "./hypothesis-verification";
import type { ImpactStateDiff } from "./impact-state";
import type { ImpactTransactionTrace } from "./impact-trace";

export const PROTOCOL_GRAPH_SCHEMA = "contracthunter-protocol-graph-v1" as const;
export const PROTOCOL_GRAPH_LIMITS = {
  sourceUnits: 5_000, nodes: 20_000, edges: 100_000, classifications: 5_000,
  evidencePerFact: 8, reasonsPerFact: 8, characteristicsPerNode: 16,
  warnings: 256, overlayEntries: 10_000,
} as const;
export const protocolNodeKinds = ["contract", "function", "role", "token", "external-protocol",
  "oracle", "proxy", "library", "interface", "external-actor"] as const;
export const protocolEdgeKinds = ["calls", "inherits", "implements", "uses-library", "reads", "writes",
  "transfers", "controls", "upgrades", "delegates", "prices", "external-call", "finding-related",
  "executed-call", "observed-transfer", "state-changed"] as const;
export const repositoryClasses = ["core", "interface", "library", "mock", "test", "deployment",
  "periphery", "dependency", "frontend", "supporting", "unknown"] as const;
export const securityCharacteristics = ["handles-assets", "external-entry-point", "external-call",
  "privileged-operation", "oracle-dependent", "upgradeable", "delegatecall", "payable",
  "token-transfer", "accounting-state", "callback-hook", "finding-present", "proxy",
  "implementation", "token-like", "oracle-like"] as const;
export const graphEvidenceOrigins = ["contracthunter-parser", "slither", "aderyn", "compiler",
  "repository-mapper", "finding", "impact-state", "impact-trace", "manual-override"] as const;

const uuid = z.string().uuid();
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
export const protocolRepositoryPathSchema = z.string().min(1).max(500).refine((value) =>
  !value.startsWith("/") && !value.includes("\\") && !value.includes("\0") &&
  value.split("/").every((part) => part !== "." && part !== ".." && /^[A-Za-z0-9_@+.-]+$/.test(part)),
"must be a safe repository-relative path");
const identifier = z.string().min(1).max(1_200).regex(/^[^\x00-\x1f]+$/);
const label = z.string().min(1).max(200).regex(/^[^\x00-\x1f]+$/);
const reason = z.string().min(1).max(128).regex(/^[a-z][a-z0-9-]*$/);
const graphIdSchema = z.string().regex(/^pg:[a-f0-9]{64}$/);
const nodeIdSchema = z.string().regex(/^pn:[a-f0-9]{64}$/);
const edgeIdSchema = z.string().regex(/^pe:[a-f0-9]{64}$/);

export const protocolSourceLocationSchema = z.object({
  sourceUnitName: repositorySolidityPathSchema,
  startLine: z.number().int().positive(), endLine: z.number().int().positive(),
  startColumn: z.number().int().nonnegative().nullable(), endColumn: z.number().int().nonnegative().nullable(),
  startByte: z.number().int().nonnegative().nullable(), endByte: z.number().int().nonnegative().nullable(),
}).strict().refine((value) => value.endLine >= value.startLine &&
  (value.startLine !== value.endLine || value.startColumn === null || value.endColumn === null ||
    value.endColumn >= value.startColumn) &&
  ((value.startByte === null && value.endByte === null) ||
    (value.startByte !== null && value.endByte !== null && value.endByte >= value.startByte)),
"invalid source range");
export type ProtocolSourceLocation = z.infer<typeof protocolSourceLocationSchema>;

export const graphEvidenceSchema = z.object({
  origin: z.enum(graphEvidenceOrigins), producerVersion: z.string().min(1).max(80),
  source: protocolSourceLocationSchema.nullable(), referenceId: identifier.nullable(),
}).strict();
export type GraphEvidence = z.infer<typeof graphEvidenceSchema>;

export const repositoryClassificationSchema = z.object({
  effective: z.enum(repositoryClasses), automatic: z.enum(repositoryClasses),
  automaticOrigin: z.enum(["path-pattern", "compiler-type", "inheritance", "unknown"]),
  reasons: z.array(reason).max(PROTOCOL_GRAPH_LIMITS.reasonsPerFact),
  override: z.object({ value: z.enum(repositoryClasses), reason: reason }).strict().nullable(),
}).strict().refine((value) => value.effective === (value.override?.value ?? value.automatic),
  "effective classification must retain its automatic and override provenance");
export type RepositoryClassification = z.infer<typeof repositoryClassificationSchema>;

const traits = z.array(z.object({ kind: z.enum(securityCharacteristics),
  evidence: z.array(graphEvidenceSchema).min(1).max(PROTOCOL_GRAPH_LIMITS.evidencePerFact) }).strict())
  .max(PROTOCOL_GRAPH_LIMITS.characteristicsPerNode);
const nodeBase = z.object({
  id: nodeIdSchema, key: identifier, name: label,
  source: protocolSourceLocationSchema.nullable(),
  evidence: z.array(graphEvidenceSchema).min(1).max(PROTOCOL_GRAPH_LIMITS.evidencePerFact),
  characteristics: traits,
}).strict();
const contractNode = nodeBase.extend({
  kind: z.enum(["contract", "interface", "library"]),
  qualifiedName: identifier, contractKind: z.enum(["contract", "interface", "library"]),
  repositoryClassification: repositoryClassificationSchema,
}).strict();
const functionNode = nodeBase.extend({
  kind: z.literal("function"), contractId: nodeIdSchema,
  signature: z.string().min(1).max(256).regex(/^[^\x00-\x1f]+$/),
  visibility: z.enum(["public", "external", "internal", "private", "unknown"]),
  mutability: z.enum(["pure", "view", "nonpayable", "payable", "unknown"]),
  modifiers: z.array(label).max(32), entryPoint: z.enum(["yes", "no", "unknown"]),
}).strict();
const conceptNode = nodeBase.extend({
  kind: z.enum(["role", "token", "external-protocol", "oracle", "proxy", "external-actor"]),
  identityState: z.enum(["known", "likely", "unknown", "unclassified"]),
  representedContractId: nodeIdSchema.nullable(),
}).strict();
export const protocolGraphNodeSchema = z.discriminatedUnion("kind", [
  contractNode.extend({ kind: z.literal("contract") }),
  contractNode.extend({ kind: z.literal("interface") }),
  contractNode.extend({ kind: z.literal("library") }),
  functionNode,
  ...(["role", "token", "external-protocol", "oracle", "proxy", "external-actor"] as const)
    .map((kind) => conceptNode.extend({ kind: z.literal(kind) })),
]);
export type ProtocolGraphNode = z.infer<typeof protocolGraphNodeSchema>;

export const protocolGraphEdgeSchema = z.object({
  id: edgeIdSchema, key: identifier, kind: z.enum(protocolEdgeKinds),
  from: nodeIdSchema, to: nodeIdSchema, origin: z.enum(["static", "runtime", "finding"]),
  reasons: z.array(reason).min(1).max(PROTOCOL_GRAPH_LIMITS.reasonsPerFact),
  evidence: z.array(graphEvidenceSchema).min(1).max(PROTOCOL_GRAPH_LIMITS.evidencePerFact),
  source: protocolSourceLocationSchema.nullable(),
  fromFunctionId: nodeIdSchema.nullable(), toFunctionId: nodeIdSchema.nullable(),
}).strict();
export type ProtocolGraphEdge = z.infer<typeof protocolGraphEdgeSchema>;

const producerSchema = z.object({ origin: z.enum(graphEvidenceOrigins), version: z.string().min(1).max(80) }).strict();
export const protocolGraphSchema = z.object({
  schema: z.literal(PROTOCOL_GRAPH_SCHEMA), id: graphIdSchema, scanId: uuid,
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/), extractorVersion: z.string().min(1).max(80),
  producers: z.array(producerSchema).min(1).max(16),
  sourceUnits: z.array(z.object({
    sourceUnitName: repositorySolidityPathSchema, snapshotSourceKey: repositorySolidityPathSchema.nullable(),
    rawSha256: sha256.nullable(), byteLength: z.number().int().nonnegative().nullable(),
    identityStatus: z.enum(["authoritative", "reported"]),
  }).strict()).max(PROTOCOL_GRAPH_LIMITS.sourceUnits),
  nodes: z.array(protocolGraphNodeSchema).max(PROTOCOL_GRAPH_LIMITS.nodes),
  edges: z.array(protocolGraphEdgeSchema).max(PROTOCOL_GRAPH_LIMITS.edges),
  classifications: z.array(z.object({ repositoryPath: protocolRepositoryPathSchema,
    value: repositoryClassificationSchema }).strict()).max(PROTOCOL_GRAPH_LIMITS.classifications),
  warnings: z.array(z.object({ code: reason, sourceUnitName: repositorySolidityPathSchema.nullable() }).strict())
    .max(PROTOCOL_GRAPH_LIMITS.warnings),
}).strict();
export type ProtocolGraph = z.infer<typeof protocolGraphSchema>;

function framedHash(domain: string, values: readonly unknown[]): string {
  return createHash("sha256").update(domain).update("\0").update(JSON.stringify(values)).digest("hex");
}
export function protocolGraphId(scanId: string, resolvedCommit: string, extractorVersion: string,
  producers: readonly { origin: string; version: string }[]): string {
  return `pg:${framedHash(PROTOCOL_GRAPH_SCHEMA, [scanId, resolvedCommit, extractorVersion,
    [...producers].sort((a, b) => a.origin.localeCompare(b.origin) || a.version.localeCompare(b.version))])}`;
}
export function contractGraphKey(sourceUnitName: string, contractName: string): string {
  repositorySolidityPathSchema.parse(sourceUnitName);
  return JSON.stringify([sourceUnitName, contractName]);
}
export function functionGraphKey(contractKey: string, signature: string): string {
  return JSON.stringify([contractKey, signature]);
}
export function protocolNodeId(scanId: string, kind: typeof protocolNodeKinds[number], key: string): string {
  return `pn:${framedHash("contracthunter-protocol-node-v1", [scanId, kind, key])}`;
}
export function protocolEdgeId(scanId: string, kind: typeof protocolEdgeKinds[number], from: string,
  to: string, key: string): string {
  return `pe:${framedHash("contracthunter-protocol-edge-v1", [scanId, kind, from, to, key])}`;
}

/** O(nodes + edges + source references); cycles are valid. */
export function validateProtocolGraph(input: unknown): ProtocolGraph {
  if (input && typeof input === "object" && !Array.isArray(input)) {
    const raw = input as Record<string, unknown>;
    for (const [field, limit] of [["sourceUnits", PROTOCOL_GRAPH_LIMITS.sourceUnits],
      ["nodes", PROTOCOL_GRAPH_LIMITS.nodes], ["edges", PROTOCOL_GRAPH_LIMITS.edges],
      ["classifications", PROTOCOL_GRAPH_LIMITS.classifications],
      ["warnings", PROTOCOL_GRAPH_LIMITS.warnings]] as const)
      if (Array.isArray(raw[field]) && raw[field].length > limit) throw Error("protocol_graph_bounds_exceeded");
  }
  const graph = protocolGraphSchema.parse(input);
  if (graph.id !== protocolGraphId(graph.scanId, graph.resolvedCommit, graph.extractorVersion, graph.producers))
    throw Error("protocol_graph_identity_invalid");
  const sources = new Map(graph.sourceUnits.map((source) => [source.sourceUnitName, source]));
  const producerKeys = new Set(graph.producers.map((producer) => `${producer.origin}\0${producer.version}`));
  if (producerKeys.size !== graph.producers.length) throw Error("protocol_graph_producer_invalid");
  if (sources.size !== graph.sourceUnits.length || graph.sourceUnits.some((source) =>
    source.identityStatus === "authoritative" ? !source.snapshotSourceKey || !source.rawSha256 ||
      source.byteLength === null :
      !!source.snapshotSourceKey || !!source.rawSha256 || source.byteLength !== null))
    throw Error("protocol_graph_source_invalid");
  const checkSource = (source: ProtocolSourceLocation | null) => {
    if (source && (!sources.has(source.sourceUnitName) ||
      source.endByte !== null && sources.get(source.sourceUnitName)!.byteLength !== null &&
        source.endByte > sources.get(source.sourceUnitName)!.byteLength!))
      throw Error("protocol_graph_source_invalid");
  };
  const nodes = new Map<string, ProtocolGraphNode>();
  const keys = new Set<string>();
  for (const node of graph.nodes) {
    if (nodes.has(node.id) || keys.has(`${node.kind}\0${node.key}`) ||
      node.id !== protocolNodeId(graph.scanId, node.kind, node.key)) throw Error("protocol_graph_node_invalid");
    checkSource(node.source);
    for (const evidence of [...node.evidence, ...node.characteristics.flatMap((trait) => trait.evidence)]) {
      checkSource(evidence.source);
      if (!producerKeys.has(`${evidence.origin}\0${evidence.producerVersion}`) ||
        ["finding", "impact-state", "impact-trace"].includes(evidence.origin))
        throw Error("protocol_graph_evidence_invalid");
    }
    if (new Set(node.characteristics.map((trait) => trait.kind)).size !== node.characteristics.length ||
      node.characteristics.some((trait) => trait.kind === "finding-present"))
      throw Error("protocol_graph_characteristics_invalid");
    if ("contractKind" in node &&
      (!node.source || node.contractKind !== node.kind ||
        node.key !== contractGraphKey(node.source.sourceUnitName, node.name) ||
        node.qualifiedName !== `${node.source.sourceUnitName}:${node.name}`))
      throw Error("protocol_graph_contract_invalid");
    nodes.set(node.id, node); keys.add(`${node.kind}\0${node.key}`);
  }
  for (const node of graph.nodes) {
    if (node.kind === "function") {
      const owner = nodes.get(node.contractId);
      if (!owner || !["contract", "interface", "library"].includes(owner.kind) ||
        !owner.source || !node.source || node.source.sourceUnitName !== owner.source.sourceUnitName ||
        node.key !== functionGraphKey(owner.key, node.signature) ||
        node.signature.split("(", 1)[0] !== node.name)
        throw Error("protocol_graph_function_owner_invalid");
    } else if ("representedContractId" in node && node.representedContractId !== null) {
      const owner = nodes.get(node.representedContractId);
      if (!owner || !["contract", "interface", "library"].includes(owner.kind))
        throw Error("protocol_graph_concept_binding_invalid");
    }
  }
  const edgeIds = new Set<string>();
  for (const edge of graph.edges) {
    if (edgeIds.has(edge.id) || edge.id !== protocolEdgeId(graph.scanId, edge.kind, edge.from, edge.to, edge.key) ||
      !nodes.has(edge.from) || !nodes.has(edge.to) ||
      edge.fromFunctionId !== null && nodes.get(edge.fromFunctionId)?.kind !== "function" ||
      edge.toFunctionId !== null && nodes.get(edge.toFunctionId)?.kind !== "function" ||
      edge.fromFunctionId !== null && edge.fromFunctionId !== edge.from &&
        (nodes.get(edge.fromFunctionId) as Extract<ProtocolGraphNode, { kind: "function" }>).contractId !== edge.from ||
      edge.toFunctionId !== null && edge.toFunctionId !== edge.to &&
        (nodes.get(edge.toFunctionId) as Extract<ProtocolGraphNode, { kind: "function" }>).contractId !== edge.to ||
      edge.origin !== "static" ||
      ["executed-call", "observed-transfer", "state-changed", "finding-related"].includes(edge.kind))
      throw Error("protocol_graph_edge_invalid");
    checkSource(edge.source);
    for (const evidence of edge.evidence) {
      checkSource(evidence.source);
      if (!producerKeys.has(`${evidence.origin}\0${evidence.producerVersion}`) ||
        ["finding", "impact-state", "impact-trace"].includes(evidence.origin))
        throw Error("protocol_graph_evidence_invalid");
    }
    edgeIds.add(edge.id);
  }
  const classified = new Set<string>();
  for (const item of graph.classifications) {
    if (classified.has(item.repositoryPath))
      throw Error("protocol_graph_classification_invalid");
    classified.add(item.repositoryPath);
  }
  for (const warning of graph.warnings) if (warning.sourceUnitName && !sources.has(warning.sourceUnitName))
    throw Error("protocol_graph_warning_invalid");
  return graph;
}

const overlayBase = z.object({ schema: z.literal("contracthunter-protocol-overlay-v1"),
  graphId: graphIdSchema, executionId: uuid.nullable() }).strict();
export const protocolGraphOverlaySchema = z.discriminatedUnion("kind", [
  overlayBase.extend({ kind: z.literal("finding"), entries: z.array(z.object({
    findingId: uuid, nodeId: nodeIdSchema.nullable(), edgeId: edgeIdSchema.nullable(),
  }).strict()).max(PROTOCOL_GRAPH_LIMITS.overlayEntries) }),
  overlayBase.extend({ kind: z.literal("impact-state"), entries: z.array(z.object({
    diffId: uuid, changeId: identifier, nodeId: nodeIdSchema,
  }).strict()).max(PROTOCOL_GRAPH_LIMITS.overlayEntries) }),
  overlayBase.extend({ kind: z.literal("impact-trace"), entries: z.array(z.object({
    traceId: uuid, transactionHash: z.string().regex(/^0x[a-f0-9]{64}$/), nodeOrdinal: z.number().int().nonnegative(),
    fromNodeId: nodeIdSchema, toNodeId: nodeIdSchema,
  }).strict()).max(PROTOCOL_GRAPH_LIMITS.overlayEntries) }),
]);
export type ProtocolGraphOverlay = z.infer<typeof protocolGraphOverlaySchema>;

export function validateProtocolGraphOverlay(graph: ProtocolGraph, input: unknown): ProtocolGraphOverlay {
  if (input && typeof input === "object" && !Array.isArray(input) &&
    Array.isArray((input as Record<string, unknown>).entries) &&
    ((input as Record<string, unknown>).entries as unknown[]).length > PROTOCOL_GRAPH_LIMITS.overlayEntries)
    throw Error("protocol_graph_overlay_bounds_exceeded");
  const overlay = protocolGraphOverlaySchema.parse(input);
  if (overlay.graphId !== graph.id || overlay.kind === "finding" && overlay.executionId !== null ||
    overlay.kind !== "finding" && overlay.executionId === null) throw Error("protocol_graph_overlay_binding_invalid");
  const nodes = new Set(graph.nodes.map((node) => node.id));
  const edges = new Set(graph.edges.map((edge) => edge.id));
  const identities = new Set<string>();
  for (const entry of overlay.entries) {
    const identity = overlay.kind === "finding" ? (() => {
      const finding = entry as Extract<ProtocolGraphOverlay, {kind:"finding"}>["entries"][number];
      return `${finding.findingId}:${finding.nodeId ?? ""}:${finding.edgeId ?? ""}`;
    })() :
      overlay.kind === "impact-state" ? (entry as Extract<ProtocolGraphOverlay, {kind:"impact-state"}>["entries"][number]).changeId :
        `${(entry as Extract<ProtocolGraphOverlay, {kind:"impact-trace"}>["entries"][number]).traceId}:${(entry as Extract<ProtocolGraphOverlay, {kind:"impact-trace"}>["entries"][number]).nodeOrdinal}`;
    if (identities.has(identity)) throw Error("protocol_graph_overlay_duplicate");
    identities.add(identity);
    if (overlay.kind === "finding") {
      const finding = entry as Extract<ProtocolGraphOverlay, {kind:"finding"}>["entries"][number];
      if ((!finding.nodeId && !finding.edgeId) || finding.nodeId && !nodes.has(finding.nodeId) ||
        finding.edgeId && !edges.has(finding.edgeId)) throw Error("protocol_graph_overlay_target_invalid");
    } else if (overlay.kind === "impact-state") {
      const state = entry as Extract<ProtocolGraphOverlay, {kind:"impact-state"}>["entries"][number];
      if (!nodes.has(state.nodeId)) throw Error("protocol_graph_overlay_target_invalid");
    } else {
      const trace = entry as Extract<ProtocolGraphOverlay, {kind:"impact-trace"}>["entries"][number];
      if (!nodes.has(trace.fromNodeId) || !nodes.has(trace.toNodeId))
        throw Error("protocol_graph_overlay_target_invalid");
    }
  }
  return overlay;
}

/** Providers yield facts only; the coordinator validates and joins them later. */
export interface ProtocolGraphExtractor<Output> {
  readonly origin: typeof graphEvidenceOrigins[number];
  readonly version: string;
  extract(input: Readonly<{ scanId: string; resolvedCommit: string }>): Promise<Output>;
}
export type FindingGraphAdapter = (graph: ProtocolGraph, findingIds: readonly string[]) => ProtocolGraphOverlay;
export type ImpactStateGraphAdapter = (graph: ProtocolGraph, diff: ImpactStateDiff) => ProtocolGraphOverlay;
export type ImpactTraceGraphAdapter = (graph: ProtocolGraph, traces: readonly ImpactTransactionTrace[]) => ProtocolGraphOverlay;
