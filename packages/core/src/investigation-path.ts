import { createHash } from "node:crypto";
import { z } from "zod";
import { buildFunctionExplorerModel, type FunctionOperation } from "./function-explorer";
import { protocolSourceLocationSchema, graphEvidenceSchema, type ProtocolGraphEdge, type ProtocolGraphNode } from "./protocol-graph";
import { validateStaticProtocolGraphArtifact, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { deriveAllSecurityViews, validateSecurityView, type SecurityViewResult } from "./security-view";

/** Static research context only. A path does not establish a runtime or exploitable route. */
export const INVESTIGATION_PATH_SCHEMA = "contracthunter-investigation-path-v1" as const;
export const INVESTIGATION_PATH_DERIVATION_VERSION = "contracthunter-investigation-path-deriver-v1" as const;
export const INVESTIGATION_PATH_LIMITS = { findingRefs: 32, targets: 32, paths: 24, depth: 3,
  exploredEdges: 2048, steps: 5, operations: 48, warnings: 16, evidencePerStep: 8 } as const;
export const investigationSubjectTypes = ["finding", "investigation", "hypothesis"] as const;
export const investigationPathKinds = ["local-context", "caller-chain", "callee-chain", "privilege-context",
  "oracle-context", "upgrade-context", "asset-operation-context"] as const;
export const investigationPathExplanationKeys = ["finding", "review-cue", "external-call", "delegatecall",
  "owner-control", "role-control", "oracle-dependency", "proxy", "token-transfer", "native-value-transfer"] as const;
const uuid = z.string().uuid(), nodeId = z.string().regex(/^pn:[a-f0-9]{64}$/), edgeId = z.string().regex(/^pe:[a-f0-9]{64}$/);
const subjectSchema = z.object({ type: z.enum(investigationSubjectTypes), id: uuid,
  findingIds: z.array(uuid).max(INVESTIGATION_PATH_LIMITS.findingRefs), linksTruncated: z.boolean().optional() }).strict();
const stepSchema = z.object({ ordinal: z.number().int().nonnegative(), nodeId, nodeKind: z.string().max(32),
  label: z.string().max(256), viaEdgeId: edgeId.nullable(), relationship: z.string().max(32).nullable(),
  explanationKey: z.enum(investigationPathExplanationKeys),
  reasons: z.array(z.string().max(128)).max(8), source: protocolSourceLocationSchema.nullable(),
  provenance: z.array(graphEvidenceSchema).max(INVESTIGATION_PATH_LIMITS.evidencePerStep),
  findingIds: z.array(uuid).max(INVESTIGATION_PATH_LIMITS.findingRefs),
  uncertainty: z.enum(["resolved", "unresolved-target", "source-unavailable"]) }).strict();
const pathSchema = z.object({ id: z.string().regex(/^ip:[a-f0-9]{64}$/), kind: z.enum(investigationPathKinds),
  targetNodeId: nodeId, nodeIds: z.array(nodeId).min(1).max(INVESTIGATION_PATH_LIMITS.steps),
  edgeIds: z.array(edgeId).max(INVESTIGATION_PATH_LIMITS.steps - 1),
  steps: z.array(stepSchema).min(1).max(INVESTIGATION_PATH_LIMITS.steps),
  completeness: z.enum(["complete-within-bounds", "partial", "truncated", "unresolved"]),
  securityViews: z.array(z.string().max(32)).max(7) }).strict();
const operationRef = z.object({ functionId: nodeId, operationId: z.string().regex(/^fo:[a-f0-9]{64}$/),
  kind: z.string().max(40), source: protocolSourceLocationSchema, resolution: z.enum(["resolved", "unresolved", "not-applicable"]) }).strict();
export const investigationPathResultSchema = z.object({ schema: z.literal(INVESTIGATION_PATH_SCHEMA),
  derivationVersion: z.literal(INVESTIGATION_PATH_DERIVATION_VERSION), scanId: uuid,
  protocolGraphId: z.string().regex(/^pg:[a-f0-9]{64}$/), graphContentSha256: z.string().regex(/^[a-f0-9]{64}$/),
  subject: subjectSchema, mapping: z.enum(["mapped", "partially-mapped", "unmapped"]),
  coverage: z.enum(["complete-within-bounds", "partial", "truncated", "unresolved"]),
  targetNodeIds: z.array(nodeId).max(INVESTIGATION_PATH_LIMITS.targets), paths: z.array(pathSchema).max(INVESTIGATION_PATH_LIMITS.paths),
  operations: z.array(operationRef).max(INVESTIGATION_PATH_LIMITS.operations),
  warnings: z.array(z.enum(["finding-unmapped", "finding-partially-mapped", "subject-links-truncated", "contract-level-only",
    "unresolved-call-target", "path-limit-reached", "traversal-limit-reached", "source-unavailable", "static-only"])).max(INVESTIGATION_PATH_LIMITS.warnings),
  runtimeOverlay: z.object({ executionTrace: z.literal("not-attached"), stateDiff: z.literal("not-attached") }).strict(),
  contentSha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
export type InvestigationPathResult = z.infer<typeof investigationPathResultSchema>;
export type InvestigationPathSubject = z.infer<typeof subjectSchema>;
/** Future exact overlay attachment only; no observed fact is included in static derivation. */
export type InvestigationPathOverlayReference = { kind: "impact-trace" | "impact-state"; executionId: string;
  artifactId: string; pathId: string; nodeId: string; operationId: string | null };
export function validateInvestigationPathOverlayReferences(result: InvestigationPathResult,
  refs: readonly InvestigationPathOverlayReference[]): void {
  const ids = new Set(result.paths.map((path) => path.id));
  const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
  if (refs.length > 256 || refs.some((ref) => !["impact-trace", "impact-state"].includes(ref.kind) ||
    !uuidPattern.test(ref.executionId) || !uuidPattern.test(ref.artifactId) || !ids.has(ref.pathId) ||
    !result.paths.some((path) => path.id === ref.pathId && path.nodeIds.includes(ref.nodeId)) ||
    ref.operationId !== null && !result.operations.some((operation) =>
      operation.operationId === ref.operationId && operation.functionId === ref.nodeId)))
    throw Error("investigation_path_overlay_reference_invalid");
}
type Path = InvestigationPathResult["paths"][number];
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function hash(domain: string, value: unknown): string { return createHash("sha256").update(domain).update("\0").update(canonical(value)).digest("hex"); }
export function validateInvestigationPathResult(input: unknown): InvestigationPathResult {
  const result = investigationPathResultSchema.parse(input);
  const { contentSha256, ...content } = result;
  if (hash(INVESTIGATION_PATH_SCHEMA, content) !== contentSha256 || result.paths.some((path) =>
    path.steps.length !== path.nodeIds.length || path.edgeIds.length !== path.nodeIds.length - 1 ||
    path.steps.some((step, index) => step.ordinal !== index || step.nodeId !== path.nodeIds[index] ||
      step.viaEdgeId !== (index ? path.edgeIds[index - 1] : null)))) throw Error("investigation_path_integrity_invalid");
  return result;
}
const callKinds = new Set<ProtocolGraphEdge["kind"]>(["calls", "external-call", "delegates"]);
function exactCall(edge: ProtocolGraphEdge, byId: Map<string, ProtocolGraphNode>): boolean {
  return edge.origin === "static" && callKinds.has(edge.kind) && byId.get(edge.from)?.kind === "function" &&
    byId.get(edge.to)?.kind === "function" && edge.fromFunctionId === edge.from && edge.toFunctionId === edge.to;
}
/** Derives bounded static neighborhoods from already persisted, exact graph identities. */
export function deriveInvestigationPaths(artifactInput: StaticProtocolGraphArtifact, subjectInput: InvestigationPathSubject,
  viewsInput?: readonly SecurityViewResult[]): InvestigationPathResult {
  const artifact = validateStaticProtocolGraphArtifact(artifactInput), subject = subjectSchema.parse(subjectInput);
  const graph = artifact.graph, byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const views = viewsInput ? viewsInput.map((view) => validateSecurityView(artifact, view)) : deriveAllSecurityViews(artifact);
  const findingIds = [...new Set(subject.findingIds)].sort();
  if (subject.type === "finding" && (findingIds.length !== 1 || findingIds[0] !== subject.id)) throw Error("investigation_path_subject_invalid");
  const selected = new Set(findingIds), links = artifact.findingLinks.filter((link) => selected.has(link.findingId));
  const targetNodeIds = [...new Set(links.map((link) => link.nodeId))].sort().slice(0, INVESTIGATION_PATH_LIMITS.targets);
  const warnings = new Set<InvestigationPathResult["warnings"][number]>(["static-only"]);
  if (!targetNodeIds.length) warnings.add("finding-unmapped");
  else if (new Set(links.map((link) => link.findingId)).size < findingIds.length) warnings.add("finding-partially-mapped");
  if (subject.linksTruncated) warnings.add("subject-links-truncated");
  if (targetNodeIds.some((id) => byId.get(id)?.kind !== "function")) warnings.add("contract-level-only");
  const edgeById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const incoming = new Map<string, ProtocolGraphEdge[]>(), outgoing = new Map<string, ProtocolGraphEdge[]>();
  for (const edge of graph.edges) {
    if (edge.origin !== "static") continue;
    const before = outgoing.get(edge.from) ?? []; before.push(edge); outgoing.set(edge.from, before);
    const after = incoming.get(edge.to) ?? []; after.push(edge); incoming.set(edge.to, after);
  }
  for (const group of [...incoming.values(), ...outgoing.values()]) group.sort((a, b) => a.id.localeCompare(b.id));
  const paths: Path[] = [], seen = new Set<string>();
  let explored = 0, limitReached = false;
  const memberships = (ids: readonly string[]) => views.filter((view) =>
    ids.some((id) => view.nodes.some((node) => node.id === id) || view.annotations.some((annotation) => annotation.nodeId === id)))
    .map((view) => view.viewType).sort();
  const addPath = (kind: Path["kind"], targetNodeId: string, nodeIds: string[], edgeIds: string[],
    completeness: Path["completeness"] = "complete-within-bounds",
    annotation?: SecurityViewResult["annotations"][number]) => {
    if (paths.length >= INVESTIGATION_PATH_LIMITS.paths) { limitReached = true; return; }
    if (nodeIds.length > INVESTIGATION_PATH_LIMITS.steps || new Set(nodeIds).size !== nodeIds.length) return;
    const key = `${kind}:${targetNodeId}:${edgeIds.join(":")}:${nodeIds.join(":")}`;
    if (seen.has(key)) return; seen.add(key);
    const steps = nodeIds.map((id, ordinal) => {
      const node = byId.get(id)!; const edge = ordinal ? edgeById.get(edgeIds[ordinal - 1])! : null;
      const explanationKey: Path["steps"][number]["explanationKey"] = edge?.kind === "external-call" ? "external-call" : edge?.kind === "delegates" ? "delegatecall" :
        edge?.kind === "controls" ? edge.reasons.includes("msg-sender-owner-guard") ? "owner-control" : "role-control" :
        edge?.kind === "prices" ? "oracle-dependency" : edge?.kind === "upgrades" ? "proxy" :
        annotation?.kind === "token-transfer-like" ? "token-transfer" :
        annotation?.kind === "native-value-transfer" ? "native-value-transfer" : edge ? "review-cue" : "finding";
      return { ordinal, nodeId: id, nodeKind: node.kind, label: node.kind === "function" ? node.signature : node.name,
        viaEdgeId: edge?.id ?? null, relationship: edge?.kind ?? null,
        explanationKey,
        reasons: edge?.reasons ?? annotation?.reasons.map((reason) => reason.code) ?? ["finding-linked"],
        source: edge?.source ?? annotation?.source ?? node.source,
        provenance: (edge?.evidence ?? annotation?.reasons.flatMap((reason) => reason.evidence) ?? node.evidence)
          .slice(0, INVESTIGATION_PATH_LIMITS.evidencePerStep),
        findingIds: links.filter((link) => link.nodeId === id).map((link) => link.findingId).sort(),
        uncertainty: node.kind === "external-actor" && node.identityState === "unknown" ? "unresolved-target" as const :
          edge?.source || annotation?.source || node.source ? "resolved" as const : "source-unavailable" as const };
    });
    const state = steps.some((step) => step.uncertainty === "unresolved-target") ? "unresolved" :
      steps.some((step) => step.uncertainty === "source-unavailable") ? "partial" : completeness;
    if (state === "unresolved" && edgeIds.some((id) => callKinds.has(edgeById.get(id)!.kind))) warnings.add("unresolved-call-target");
    if (state === "partial") warnings.add("source-unavailable");
    paths.push({ id: `ip:${hash(INVESTIGATION_PATH_SCHEMA, [graph.id, subject.type, subject.id, kind, targetNodeId, nodeIds, edgeIds])}`,
      kind, targetNodeId, nodeIds, edgeIds, steps, completeness: state,
      securityViews: memberships(nodeIds) });
  };
  const operations: InvestigationPathResult["operations"] = [];
  const operationKinds = new Set<FunctionOperation["kind"]>(["condition", "state-read", "state-write", "external-call",
    "low-level-call", "delegatecall", "staticcall", "token-transfer-like", "native-transfer", "modifier", "assembly"]);
  for (const targetId of targetNodeIds) {
    const target = byId.get(targetId)!;
    addPath("local-context", targetId, [targetId], []);
    const ownerId = target.kind === "function" ? target.contractId : targetId;
    if (target.kind === "function") {
      const model = buildFunctionExplorerModel(artifact, ownerId, target.id);
      if (model) for (const op of model.operations) if (operationKinds.has(op.kind) && operations.length < INVESTIGATION_PATH_LIMITS.operations)
        operations.push({ functionId: target.id, operationId: op.id, kind: op.kind, source: op.source, resolution: op.resolution });
      for (const edge of incoming.get(target.id) ?? []) if (exactCall(edge, byId))
        addPath("local-context", targetId, [edge.from, target.id], [edge.id]);
      for (const edge of outgoing.get(target.id) ?? []) if (callKinds.has(edge.kind)) {
        addPath("local-context", targetId, [target.id, edge.to], [edge.id]);
        const destination = byId.get(edge.to);
        if (destination?.kind === "external-actor" && destination.identityState === "unknown") warnings.add("unresolved-call-target");
      }
      const walk = (direction: "caller-chain" | "callee-chain") => {
        const queue = [{ ids: [target.id], edges: [] as string[] }];
        while (queue.length && paths.length < INVESTIGATION_PATH_LIMITS.paths && explored < INVESTIGATION_PATH_LIMITS.exploredEdges) {
          const current = queue.shift()!;
          if (current.edges.length >= INVESTIGATION_PATH_LIMITS.depth) continue;
          for (const edge of direction === "caller-chain" ? incoming.get(current.ids[0]) ?? [] : outgoing.get(current.ids.at(-1)!) ?? []) {
            if (++explored > INVESTIGATION_PATH_LIMITS.exploredEdges) break;
            if (!exactCall(edge, byId)) continue;
            const nextId = direction === "caller-chain" ? edge.from : edge.to;
            if (current.ids.includes(nextId)) continue;
            const ids = direction === "caller-chain" ? [nextId, ...current.ids] : [...current.ids, nextId];
            const edges = direction === "caller-chain" ? [edge.id, ...current.edges] : [...current.edges, edge.id];
            if (direction === "caller-chain" && byId.get(nextId)?.kind === "function" &&
              (byId.get(nextId) as Extract<ProtocolGraphNode, { kind: "function" }>).entryPoint === "yes")
              addPath(direction, targetId, ids, edges);
            if (direction === "callee-chain" && edge.kind === "external-call") addPath(direction, targetId, ids, edges);
            queue.push({ ids, edges });
          }
        }
        if (queue.length && paths.length >= INVESTIGATION_PATH_LIMITS.paths) limitReached = true;
      };
      walk("caller-chain"); walk("callee-chain");
    }
    for (const edge of graph.edges) {
      if (edge.origin !== "static") continue;
      if (edge.kind === "controls" && (edge.to === targetId || target.kind === "function" && edge.to === ownerId && edge.toFunctionId === targetId))
        addPath("privilege-context", targetId, [edge.from, edge.to], [edge.id]);
      if (edge.kind === "upgrades" && (edge.from === ownerId || edge.to === ownerId))
        addPath("upgrade-context", targetId, [edge.from, edge.to], [edge.id]);
    }
    for (const view of views) for (const edgeRef of view.edges) {
      if (!edgeRef.reasons.length) continue;
      const edge = edgeById.get(edgeRef.id);
      if (!edge || edge.origin !== "static" || ![targetId, ownerId].includes(edge.from) && ![targetId, ownerId].includes(edge.to)) continue;
      if (view.viewType === "oracle-flow") addPath("oracle-context", targetId, [edge.from, edge.to], [edge.id]);
      if (view.viewType === "money-flow") addPath("asset-operation-context", targetId, [edge.from, edge.to], [edge.id]);
      if (view.viewType === "upgradeability" && edge.kind === "upgrades") addPath("upgrade-context", targetId, [edge.from, edge.to], [edge.id]);
    }
    for (const view of views) if (view.viewType === "money-flow") for (const annotation of view.annotations)
      if (annotation.nodeId === targetId && ["token-transfer-like", "native-value-transfer"].includes(annotation.kind))
        addPath("asset-operation-context", targetId, [targetId], [], "complete-within-bounds", annotation);
  }
  if (explored >= INVESTIGATION_PATH_LIMITS.exploredEdges) warnings.add("traversal-limit-reached");
  if (limitReached) warnings.add("path-limit-reached");
  paths.sort((a, b) => investigationPathKinds.indexOf(a.kind) - investigationPathKinds.indexOf(b.kind) ||
    a.edgeIds.length - b.edgeIds.length || a.targetNodeId.localeCompare(b.targetNodeId) || a.id.localeCompare(b.id));
  operations.sort((a, b) => a.functionId.localeCompare(b.functionId) || a.source.sourceUnitName.localeCompare(b.source.sourceUnitName) ||
    (a.source.startByte ?? a.source.startLine) - (b.source.startByte ?? b.source.startLine) || a.operationId.localeCompare(b.operationId));
  const content = { schema: INVESTIGATION_PATH_SCHEMA, derivationVersion: INVESTIGATION_PATH_DERIVATION_VERSION,
    scanId: graph.scanId, protocolGraphId: graph.id, graphContentSha256: artifact.contentSha256,
    subject: { ...subject, findingIds }, mapping: targetNodeIds.length === 0 ? "unmapped" as const :
      warnings.has("finding-partially-mapped") || warnings.has("subject-links-truncated") ? "partially-mapped" as const : "mapped" as const,
    coverage: warnings.has("path-limit-reached") || warnings.has("traversal-limit-reached") || warnings.has("subject-links-truncated") ?
      "truncated" as const : !targetNodeIds.length || warnings.has("finding-partially-mapped") || warnings.has("contract-level-only") ?
        "partial" as const : warnings.has("unresolved-call-target") ? "unresolved" as const : "complete-within-bounds" as const,
    targetNodeIds, paths, operations, warnings: [...warnings].sort(),
    runtimeOverlay: { executionTrace: "not-attached" as const, stateDiff: "not-attached" as const } };
  return validateInvestigationPathResult({ ...content, contentSha256: hash(INVESTIGATION_PATH_SCHEMA, content) });
}
