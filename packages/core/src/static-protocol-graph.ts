import { createHash } from "node:crypto";
import { z } from "zod";
import { PROTOCOL_GRAPH_LIMITS, protocolGraphSchema, validateProtocolGraph } from "./protocol-graph";

export const STATIC_PROTOCOL_GRAPH_SCHEMA = "contracthunter-static-protocol-graph-v1" as const;
export const STATIC_GRAPH_EXTRACTOR_VERSION = "contracthunter-static-graph-v1" as const;
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const nodeId = z.string().regex(/^pn:[a-f0-9]{64}$/);
const path = z.string().min(1).max(500);
const name = z.string().min(1).max(200).regex(/^[^\x00-\x1f]+$/);
const location = z.object({ sourceUnitName: path, startLine: z.number().int().positive(),
  endLine: z.number().int().positive(), startColumn: z.number().int().nonnegative().nullable(),
  endColumn: z.number().int().nonnegative().nullable(), startByte: z.number().int().nonnegative().nullable(),
  endByte: z.number().int().nonnegative().nullable() }).strict();
const stateAccess = z.object({ variable: name, contractId: nodeId,
  declarationId: z.number().int().nonnegative(), source: location }).strict();
const functionFacts = z.object({ functionId: nodeId, stateReads: z.array(stateAccess).max(256),
  stateWrites: z.array(stateAccess).max(256), tokenTransferLike: z.boolean(), nativeValueTransfer: z.boolean(),
  modifierInvocations: z.array(z.object({ name, declarationId: z.number().int().nonnegative().nullable(),
    source: location }).strict()).max(32),
  lowLevelCalls: z.array(z.enum(["call", "staticcall", "delegatecall", "callcode"])).max(128),
}).strict();
const unresolved = z.object({ callerFunctionId: nodeId, source: location,
  kind: z.enum(["external-call", "internal-call", "inheritance", "library", "type"]),
  reason: z.enum(["dynamic-target", "outside-source-universe", "ambiguous-name", "unsupported-ast", "unresolved-reference"]),
  expression: name.nullable() }).strict();
const summary = z.object({ contracts: z.number().int().nonnegative(), interfaces: z.number().int().nonnegative(),
  libraries: z.number().int().nonnegative(), functions: z.number().int().nonnegative(), edges: z.number().int().nonnegative(),
  externalCalls: z.number().int().nonnegative(), entryPoints: z.number().int().nonnegative(),
  proxies: z.number().int().nonnegative(), delegatecalls: z.number().int().nonnegative(),
  findingsLinkedNodes: z.number().int().nonnegative(), unresolvedRelationships: z.number().int().nonnegative() }).strict();
export const staticProtocolGraphArtifactSchema = z.object({ schema: z.literal(STATIC_PROTOCOL_GRAPH_SCHEMA),
  repositoryMapId: z.string().regex(/^rm:[a-f0-9]{64}$/), graph: protocolGraphSchema,
  functionFacts: z.array(functionFacts).max(PROTOCOL_GRAPH_LIMITS.nodes),
  findingLinks: z.array(z.object({ findingId: z.string().uuid(), nodeId }).strict()).max(PROTOCOL_GRAPH_LIMITS.overlayEntries),
  unresolved: z.array(unresolved).max(PROTOCOL_GRAPH_LIMITS.edges), summary,
  contentSha256: sha,
}).strict();
export type StaticProtocolGraphArtifact = z.infer<typeof staticProtocolGraphArtifactSchema>;
export type StaticFunctionFacts = StaticProtocolGraphArtifact["functionFacts"][number];
export type StaticUnresolvedRelationship = StaticProtocolGraphArtifact["unresolved"][number];

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
export function staticProtocolGraphContentHash(value: Omit<StaticProtocolGraphArtifact, "contentSha256">): string {
  return createHash("sha256").update(STATIC_PROTOCOL_GRAPH_SCHEMA).update("\0").update(canonical(value)).digest("hex");
}
export function validateStaticProtocolGraphArtifact(input: unknown): StaticProtocolGraphArtifact {
  const artifact = staticProtocolGraphArtifactSchema.parse(input);
  validateProtocolGraph(artifact.graph);
  if (!artifact.graph.extractorVersion.endsWith(`:${artifact.repositoryMapId}`)) throw Error("static_graph_map_binding_invalid");
  const ids = new Set(artifact.graph.nodes.map((node) => node.id));
  const functionNodes = new Map(artifact.graph.nodes.filter((node) => node.kind === "function").map((node) => [node.id, node]));
  const functions = new Set(functionNodes.keys());
  const contracts = new Set(artifact.graph.nodes.filter((node) => ["contract", "interface", "library"].includes(node.kind)).map((node) => node.id));
  if (new Set(artifact.functionFacts.map((fact) => fact.functionId)).size !== artifact.functionFacts.length ||
    artifact.functionFacts.some((fact) => !functions.has(fact.functionId) ||
      [...fact.stateReads, ...fact.stateWrites].some((access) => !contracts.has(access.contractId) ||
        access.source.sourceUnitName !== functionNodes.get(fact.functionId)?.source?.sourceUnitName) ||
      fact.modifierInvocations.some((item) => item.source.sourceUnitName !==
        functionNodes.get(fact.functionId)?.source?.sourceUnitName)) ||
    artifact.unresolved.some((fact) => !functions.has(fact.callerFunctionId) ||
      fact.source.sourceUnitName !== functionNodes.get(fact.callerFunctionId)?.source?.sourceUnitName) ||
    artifact.findingLinks.some((link) => !ids.has(link.nodeId)) ||
    new Set(artifact.findingLinks.map((link) => `${link.findingId}:${link.nodeId}`)).size !== artifact.findingLinks.length ||
    artifact.graph.edges.some((edge) => !ids.has(edge.from) || !ids.has(edge.to))) throw Error("static_graph_binding_invalid");
  const nodes = artifact.graph.nodes;
  const count = (kind: string) => nodes.filter((node) => node.kind === kind).length;
  const expected = { contracts: count("contract"), interfaces: count("interface"), libraries: count("library"),
    functions: count("function"), edges: artifact.graph.edges.length,
    externalCalls: artifact.graph.edges.filter((edge) => edge.kind === "external-call").length,
    entryPoints: nodes.filter((node) => node.kind === "function" && node.entryPoint === "yes").length,
    proxies: nodes.filter((node) => node.kind === "contract" && node.characteristics.some((trait) => trait.kind === "proxy")).length,
    delegatecalls: artifact.functionFacts.reduce((sum, fact) => sum + fact.lowLevelCalls.filter((kind) => kind === "delegatecall").length, 0),
    findingsLinkedNodes: new Set(artifact.findingLinks.map((link) => link.nodeId)).size,
    unresolvedRelationships: artifact.unresolved.length };
  if (JSON.stringify(artifact.summary) !== JSON.stringify(expected)) throw Error("static_graph_summary_invalid");
  const { contentSha256, ...content } = artifact;
  if (staticProtocolGraphContentHash(content) !== contentSha256) throw Error("static_graph_hash_invalid");
  return artifact;
}
