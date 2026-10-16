import { createHash } from "node:crypto";
import { z } from "zod";
import { graphEvidenceSchema, protocolSourceLocationSchema,
  type GraphEvidence, type ProtocolGraphEdge, type ProtocolGraphNode,
  type ProtocolSourceLocation } from "./protocol-graph";
import { validateStaticProtocolGraphArtifact, type StaticProtocolGraphArtifact } from "./static-protocol-graph";

export const SECURITY_VIEW_SCHEMA = "contracthunter-security-view-v1" as const;
export const SECURITY_VIEW_DERIVATION_VERSION = "contracthunter-security-view-deriver-v1" as const;
export const securityViewTypes = ["money-flow", "permissions", "oracle-flow", "external-calls",
  "upgradeability", "attack-surface", "findings"] as const;
export type SecurityViewType = typeof securityViewTypes[number];
export const securityViewReasons = ["contains-included-function", "relationship-endpoint", "token-transfer",
  "native-value-transfer", "transfer-relationship", "owner-controlled", "role-controlled", "privileged-operation",
  "oracle-like-dependency", "external-call", "target-not-statically-resolved", "low-level-call",
  "delegatecall-present", "proxy", "proxy-implementation", "upgradeable", "upgrade-authority",
  "externally-callable", "payable", "state-changing", "assembly-present", "callback-hook",
  "finding-linked", "call-site-with-transfer-like-operation"] as const;
export type SecurityViewReason = typeof securityViewReasons[number];
export const SECURITY_VIEW_LIMITS = { nodes: 5_000, edges: 20_000, annotations: 20_000,
  reasonsPerItem: 8, warnings: 32, findingMetadata: 500 } as const;

const nodeId = z.string().regex(/^pn:[a-f0-9]{64}$/), edgeId = z.string().regex(/^pe:[a-f0-9]{64}$/);
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const reasonSchema = z.object({ code: z.enum(securityViewReasons), sourceKind: z.enum([
  "graph-node", "graph-edge", "node-characteristic", "function-fact", "function-syntax", "finding-link"]),
  sourceId: z.string().min(1).max(160), source: protocolSourceLocationSchema.nullable(),
  evidence: z.array(graphEvidenceSchema).max(8), explanationKey: z.enum(securityViewReasons) }).strict();
const itemSchema = z.object({ id: nodeId, reasons: z.array(reasonSchema).min(1).max(SECURITY_VIEW_LIMITS.reasonsPerItem) }).strict();
const edgeItemSchema = z.object({ id: edgeId, reasons: z.array(reasonSchema).min(1).max(SECURITY_VIEW_LIMITS.reasonsPerItem),
  callType: z.enum(["high-level", "call", "staticcall", "delegatecall", "callcode", "not-applicable"]),
  targetContext: z.enum(["internal-protocol", "dependency", "external-contract", "unresolved", "not-applicable"]) }).strict();
const annotationKinds = ["token-transfer-like", "native-value-transfer", "unresolved-call",
  "state-write", "assembly", "finding", "oracle-consumer", "entry-point", "payable-entry-point",
  "callback", "proxy-target-unresolved"] as const;
const annotationSchema = z.object({ id: z.string().regex(/^sv:[a-f0-9]{64}$/), kind: z.enum(annotationKinds),
  nodeId, graphEdgeId: edgeId.nullable(), source: protocolSourceLocationSchema.nullable(),
  targetStatus: z.enum(["resolved", "unresolved", "not-applicable"]),
  assetDirection: z.enum(["unresolved", "not-applicable"]), findingId: z.string().uuid().nullable(),
  reasons: z.array(reasonSchema).min(1).max(SECURITY_VIEW_LIMITS.reasonsPerItem) }).strict();
const warningCodes = ["view-truncated", "reasons-truncated", "oracle-evidence-unavailable",
  "access-control-extraction-unavailable", "token-identity-unresolved", "asset-direction-unresolved",
  "call-target-unresolved", "proxy-target-unresolved", "syntax-facts-unavailable",
  "finding-metadata-truncated", "graph-analysis-partial"] as const;
const metricKeys = ["assetMovingFunctions", "tokenOperations", "nativeTransfers", "unresolvedAssetTargets",
  "roles", "controlledFunctions", "upgradeControls", "pauseControls", "oracleSources", "oracleCallSites",
  "resolvedCalls", "unresolvedCalls", "lowLevelCalls", "delegatecalls", "proxies", "implementations",
  "entryPoints", "payableEntryPoints", "stateChangingEntryPoints", "assemblyFunctions", "callbacks",
  "contractsWithFindings", "functionsWithFindings", "attachedFindingRefs", "unmappedFindingRefs"] as const;
const findingMetadataSchema = z.object({ id: z.string().uuid(), detectorId: z.string().max(160).nullable(),
  title: z.string().max(200), status: z.string().max(80), source: z.string().max(80) }).strict();
export type SecurityFindingMetadata = z.infer<typeof findingMetadataSchema>;
export const securityViewSchema = z.object({ schema: z.literal(SECURITY_VIEW_SCHEMA),
  derivationVersion: z.literal(SECURITY_VIEW_DERIVATION_VERSION),
  id: z.string().regex(/^sv:[a-f0-9]{64}$/), contentSha256: sha, scanId: z.string().uuid(),
  protocolGraphId: z.string().regex(/^pg:[a-f0-9]{64}$/), graphContentSha256: sha,
  viewType: z.enum(securityViewTypes),
  nodes: z.array(itemSchema).max(SECURITY_VIEW_LIMITS.nodes),
  edges: z.array(edgeItemSchema).max(SECURITY_VIEW_LIMITS.edges),
  annotations: z.array(annotationSchema).max(SECURITY_VIEW_LIMITS.annotations),
  findingMetadata: z.array(findingMetadataSchema).max(SECURITY_VIEW_LIMITS.findingMetadata),
  summary: z.object({ nodeCount: z.number().int().nonnegative(), edgeCount: z.number().int().nonnegative(),
    annotationCount: z.number().int().nonnegative(), metrics: z.array(z.object({ key: z.enum(metricKeys),
      value: z.number().int().nonnegative() }).strict()).max(metricKeys.length) }).strict(),
  warnings: z.array(z.object({ code: z.enum(warningCodes), count: z.number().int().positive() }).strict())
    .max(SECURITY_VIEW_LIMITS.warnings),
  provenance: z.object({ graphSchema: z.literal("contracthunter-protocol-graph-v1"),
    staticArtifactSchema: z.literal("contracthunter-static-protocol-graph-v1"),
    repositoryMapId: z.string().regex(/^rm:[a-f0-9]{64}$/), extractorVersion: z.string().min(1).max(160) }).strict(),
}).strict();
export type SecurityViewResult = z.infer<typeof securityViewSchema>;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
const hash = (domain: string, value: unknown) => createHash("sha256").update(domain).update("\0")
  .update(canonical(value)).digest("hex");
function reason(code: SecurityViewReason, sourceKind: z.infer<typeof reasonSchema>["sourceKind"],
  sourceId: string, source: ProtocolSourceLocation | null, evidence: GraphEvidence[] = []): z.infer<typeof reasonSchema> {
  return { code, sourceKind, sourceId, source, evidence: evidence.slice(0, 8), explanationKey: code };
}
const sameLocation = (a: ProtocolSourceLocation | null, b: ProtocolSourceLocation | null) =>
  !!a && !!b && a.sourceUnitName === b.sourceUnitName && a.startByte !== null && b.startByte !== null &&
  a.startByte === b.startByte && a.endByte === b.endByte;
function reasonKey(item: z.infer<typeof reasonSchema>): string {
  return `${item.code}\0${item.sourceKind}\0${item.sourceId}\0${item.source?.startByte ?? ""}`;
}
function metricKey(key: typeof metricKeys[number], value: number) { return { key, value }; }

/** Read-only, direct-fact projection. No graph traversal or source-name inference. */
function deriveValidatedSecurityView(artifact: StaticProtocolGraphArtifact, viewType: SecurityViewType,
  findingMetadataInput: readonly SecurityFindingMetadata[] = []): SecurityViewResult {
  if (!securityViewTypes.includes(viewType)) throw Error("security_view_type_invalid");
  if (findingMetadataInput.length > SECURITY_VIEW_LIMITS.findingMetadata) throw Error("security_view_finding_metadata_bounds_exceeded");
  if (new Set(findingMetadataInput.map((item) => item.id)).size !== findingMetadataInput.length)
    throw Error("security_view_finding_metadata_duplicate");
  const graph = artifact.graph;
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const nodes = new Map<string, z.infer<typeof reasonSchema>[]>(), edges = new Map<string, z.infer<typeof reasonSchema>[]>();
  const annotations: SecurityViewResult["annotations"] = [], warnings = new Map<string, number>();
  const metrics = new Map<typeof metricKeys[number], number>();
  const addMetric = (key: typeof metricKeys[number], value = 1) => metrics.set(key, (metrics.get(key) ?? 0) + value);
  const warn = (code: typeof warningCodes[number], count = 1) => warnings.set(code, (warnings.get(code) ?? 0) + count);
  const addReason = (collection: Map<string, z.infer<typeof reasonSchema>[]>, id: string,
    item: z.infer<typeof reasonSchema>) => {
    const list = collection.get(id) ?? [];
    if (list.some((existing) => reasonKey(existing) === reasonKey(item))) return;
    if (list.length >= SECURITY_VIEW_LIMITS.reasonsPerItem) { warn("reasons-truncated"); return; }
    list.push(item); collection.set(id, list);
  };
  const includeNode = (id: string, why: z.infer<typeof reasonSchema>) => {
    if (!byId.has(id)) throw Error("security_view_node_reference_invalid");
    addReason(nodes, id, why);
    const node = byId.get(id)!;
    if (node.kind === "function") {
      const owner = byId.get(node.contractId)!;
      addReason(nodes, owner.id, reason("contains-included-function", "graph-node", node.id, node.source, node.evidence));
    }
  };
  const includeEdge = (edge: ProtocolGraphEdge, why: z.infer<typeof reasonSchema>) => {
    addReason(edges, edge.id, why);
    includeNode(edge.from, reason("relationship-endpoint", "graph-edge", edge.id, edge.source, edge.evidence));
    includeNode(edge.to, reason("relationship-endpoint", "graph-edge", edge.id, edge.source, edge.evidence));
  };
  const annotate = (kind: typeof annotationKinds[number], nodeIdValue: string, why: z.infer<typeof reasonSchema>,
    source: ProtocolSourceLocation | null, graphEdgeId: string | null = null,
    targetStatus: "resolved" | "unresolved" | "not-applicable" = "not-applicable",
    assetDirection: "unresolved" | "not-applicable" = "not-applicable", findingId: string | null = null) => {
    const id = `sv:${hash("contracthunter-security-view-annotation-v1", [artifact.contentSha256, viewType,
      kind, nodeIdValue, graphEdgeId, source, findingId, why.sourceId, annotations.length])}`;
    annotations.push({ id, kind, nodeId: nodeIdValue, graphEdgeId, source, targetStatus, assetDirection,
      findingId, reasons: [why] });
    includeNode(nodeIdValue, why);
  };
  const traits = (node: ProtocolGraphNode, kind: ProtocolGraphNode["characteristics"][number]["kind"]) =>
    node.characteristics.filter((item) => item.kind === kind);
  const traitReason = (node: ProtocolGraphNode, kind: ProtocolGraphNode["characteristics"][number]["kind"],
    code: SecurityViewReason) => traits(node, kind).map((item) => reason(code, "node-characteristic", node.id,
      item.evidence[0]?.source ?? node.source, item.evidence));
  const functionOwner = (id: string) => {
    const node = byId.get(id);
    return node?.kind === "function" ? byId.get(node.contractId) : node;
  };
  const callEdges = graph.edges.filter((edge) => ["calls", "external-call", "delegates"].includes(edge.kind));
  const callSites = new Map<string, ProtocolGraphEdge[]>();
  for (const edge of callEdges) if (edge.source?.startByte !== null && edge.source?.startByte !== undefined) {
    const caller = edge.fromFunctionId ?? (byId.get(edge.from)?.kind === "function" ? edge.from : null);
    if (!caller) continue;
    const key = `${caller}\0${edge.source.sourceUnitName}\0${edge.source.startByte}`;
    const list = callSites.get(key) ?? []; list.push(edge); callSites.set(key, list);
  }
  const matchingCall = (functionId: string, source: ProtocolSourceLocation | null) =>
    source?.startByte === null || !source ? [] :
      (callSites.get(`${functionId}\0${source.sourceUnitName}\0${source.startByte}`) ?? [])
        .filter((edge) => sameLocation(edge.source, source));
  const matchedCallEdges = new Set<string>();

  if (viewType === "money-flow") {
    const assetFunctions = new Set<string>();
    for (const node of graph.nodes) if (node.kind === "function") {
      for (const [trait, kind, code, metric] of [
        ["token-transfer", "token-transfer-like", "token-transfer", "tokenOperations"],
        ["native-transfer", "native-value-transfer", "native-value-transfer", "nativeTransfers"],
      ] as const) for (const why of traitReason(node, trait, code)) {
        assetFunctions.add(node.id); addMetric(metric); addMetric("unresolvedAssetTargets");
        annotate(kind, node.id, why, why.source, null, "unresolved", "unresolved");
        for (const edge of matchingCall(node.id, why.source)) if (!matchedCallEdges.has(edge.id)) {
          matchedCallEdges.add(edge.id);
          includeEdge(edge, reason("call-site-with-transfer-like-operation", "graph-edge", edge.id,
            edge.source, edge.evidence));
        }
      }
    }
    addMetric("assetMovingFunctions", assetFunctions.size);
    for (const edge of graph.edges) if (edge.kind === "transfers") includeEdge(edge,
      reason("transfer-relationship", "graph-edge", edge.id, edge.source, edge.evidence));
    if (metrics.get("unresolvedAssetTargets")) { warn("token-identity-unresolved", metrics.get("tokenOperations") ?? 0);
      warn("asset-direction-unresolved", metrics.get("unresolvedAssetTargets")!); }
  }
  if (viewType === "permissions") {
    const roles = new Set<string>(), controlled = new Set<string>();
    for (const edge of graph.edges) if (edge.kind === "controls" && byId.get(edge.from)?.kind === "role" &&
      byId.get(edge.to)?.kind === "function") {
      const role = byId.get(edge.from)!;
      const code = role.name === "owner" && edge.reasons.includes("msg-sender-owner-guard") ?
        "owner-controlled" : "role-controlled";
      includeEdge(edge, reason(code, "graph-edge", edge.id, edge.source, edge.evidence));
      roles.add(role.id); controlled.add(edge.to);
    }
    addMetric("roles", roles.size); addMetric("controlledFunctions", controlled.size);
    for (const node of graph.nodes) if (node.kind === "function")
      for (const why of traitReason(node, "privileged-operation", "privileged-operation")) includeNode(node.id, why);
    warn("access-control-extraction-unavailable");
  }
  if (viewType === "oracle-flow") {
    const oracleIds = new Set<string>(), oracleSources = new Set<string>();
    for (const node of graph.nodes) {
      const supported = node.kind === "oracle" && node.identityState === "known" ||
        traits(node, "oracle-like").length > 0;
      if (!supported) continue;
      const why = traitReason(node, "oracle-like", "oracle-like-dependency")[0] ??
        reason("oracle-like-dependency", "graph-node", node.id, node.source, node.evidence);
      includeNode(node.id, why); oracleIds.add(node.id); oracleSources.add(node.id);
      if ("representedContractId" in node && node.representedContractId) oracleIds.add(node.representedContractId);
    }
    const consumers = new Set<string>();
    for (const edge of callEdges) if (oracleIds.has(edge.to) || oracleIds.has(functionOwner(edge.to)?.id ?? "")) {
      includeEdge(edge, reason("oracle-like-dependency", "graph-edge", edge.id, edge.source, edge.evidence));
      consumers.add(edge.id);
      const caller = edge.fromFunctionId ?? (byId.get(edge.from)?.kind === "function" ? edge.from : null);
      if (caller) annotate("oracle-consumer", caller, reason("oracle-like-dependency", "graph-edge", edge.id,
        edge.source, edge.evidence), edge.source, edge.id, "resolved");
    }
    for (const edge of graph.edges) if (edge.kind === "prices" &&
      (oracleIds.has(edge.from) || oracleIds.has(functionOwner(edge.from)?.id ?? "")))
      includeEdge(edge, reason("oracle-like-dependency", "graph-edge", edge.id, edge.source, edge.evidence));
    addMetric("oracleSources", oracleSources.size); addMetric("oracleCallSites", consumers.size);
    if (!oracleIds.size) warn("oracle-evidence-unavailable");
  }
  if (viewType === "external-calls" || viewType === "attack-surface") {
    for (const edge of callEdges) if (edge.kind === "external-call" || edge.kind === "delegates" &&
      edge.reasons.some((item) => item.startsWith("low-level-delegatecall"))) {
      const target = byId.get(edge.to);
      const unresolved = target?.kind === "external-actor" && "identityState" in target &&
        target.identityState === "unknown";
      const low = edge.reasons.some((item) => item.startsWith("low-level-"));
      const code = edge.kind === "delegates" ? "delegatecall-present" : low ? "low-level-call" : "external-call";
      includeEdge(edge, reason(code, "graph-edge", edge.id, edge.source, edge.evidence));
      if (unresolved) {
        const caller = edge.fromFunctionId ?? (byId.get(edge.from)?.kind === "function" ? edge.from : null);
        if (caller) annotate("unresolved-call", caller, reason("target-not-statically-resolved",
          "graph-edge", edge.id, edge.source, edge.evidence), edge.source, edge.id, "unresolved");
        addMetric("unresolvedCalls");
      } else addMetric("resolvedCalls");
      if (low) addMetric("lowLevelCalls");
      if (edge.kind === "delegates") addMetric("delegatecalls");
    }
    if (metrics.get("unresolvedCalls")) warn("call-target-unresolved", metrics.get("unresolvedCalls")!);
  }
  if (viewType === "upgradeability") {
    const proxies = new Set<string>(), implementations = new Set<string>();
    for (const node of graph.nodes) {
      for (const why of traitReason(node, "proxy", "proxy")) { includeNode(node.id, why); proxies.add(node.id); }
      for (const why of traitReason(node, "implementation", "proxy-implementation")) {
        includeNode(node.id, why); implementations.add(node.id);
      }
      for (const why of traitReason(node, "upgradeable", "upgradeable")) includeNode(node.id, why);
    }
    for (const edge of graph.edges) if (edge.kind === "upgrades" ||
      edge.kind === "delegates" && proxies.has(edge.from)) {
      const code = edge.kind === "upgrades" ? "proxy-implementation" : "proxy";
      includeEdge(edge, reason(code, "graph-edge", edge.id, edge.source, edge.evidence));
      if (byId.get(edge.to)?.kind === "external-actor") {
        annotate("proxy-target-unresolved", edge.from, reason("target-not-statically-resolved",
          "graph-edge", edge.id, edge.source, edge.evidence), edge.source, edge.id, "unresolved");
        warn("proxy-target-unresolved");
      }
    }
    const upgradeFunctions = new Set(graph.edges.filter((edge) => edge.kind === "upgrades")
      .flatMap((edge) => edge.fromFunctionId ? [edge.fromFunctionId] : byId.get(edge.from)?.kind === "function" ? [edge.from] : []));
    const upgradeControls = new Set<string>();
    for (const edge of graph.edges) if (edge.kind === "controls" && upgradeFunctions.has(edge.toFunctionId ?? edge.to)) {
      includeEdge(edge, reason("upgrade-authority", "graph-edge", edge.id, edge.source, edge.evidence));
      upgradeControls.add(edge.id);
    }
    addMetric("proxies", proxies.size); addMetric("implementations", implementations.size);
    addMetric("upgradeControls", upgradeControls.size);
  }
  if (viewType === "attack-surface") {
    const facts = new Map(artifact.functionFacts.map((item) => [item.functionId, item]));
    const syntax = new Map((artifact.functionSyntax ?? []).map((item) => [item.functionId, item]));
    const missingSyntax = graph.nodes.filter((node) => node.kind === "function" && !syntax.has(node.id)).length;
    if (missingSyntax) warn("syntax-facts-unavailable", missingSyntax);
    for (const node of graph.nodes) if (node.kind === "function") {
      if (node.entryPoint === "yes") {
        const why = reason("externally-callable", "graph-node", node.id, node.source, node.evidence);
        annotate("entry-point", node.id, why, node.source); addMetric("entryPoints");
        if (node.mutability === "payable") {
          annotate("payable-entry-point", node.id, reason("payable", "graph-node", node.id,
            node.source, node.evidence), node.source); addMetric("payableEntryPoints");
        }
        if (node.mutability !== "view" && node.mutability !== "pure" && facts.get(node.id)?.stateWrites.length) {
          addMetric("stateChangingEntryPoints");
          for (const access of facts.get(node.id)!.stateWrites) annotate("state-write", node.id,
            reason("state-changing", "function-fact", node.id, access.source), access.source);
        }
      }
      const assembly = syntax.get(node.id)?.operations.filter((item) => item.kind === "assembly") ?? [];
      if (assembly.length) addMetric("assemblyFunctions");
      for (const item of assembly) annotate("assembly", node.id, reason("assembly-present", "function-syntax",
        `${node.id}:${item.astNodeId}`, item.source), item.source);
      for (const why of traitReason(node, "callback-hook", "callback-hook")) {
        annotate("callback", node.id, why, why.source); addMetric("callbacks");
      }
      for (const [trait, code] of [["token-transfer", "token-transfer"],
        ["native-transfer", "native-value-transfer"], ["privileged-operation", "privileged-operation"]] as const)
        for (const why of traitReason(node, trait, code)) includeNode(node.id, why);
    }
  }
  if (viewType === "findings" || viewType === "attack-surface") {
    const contracts = new Set<string>(), functions = new Set<string>(), links = new Set<string>();
    for (const link of artifact.findingLinks) {
      const node = byId.get(link.nodeId)!;
      const why = reason("finding-linked", "finding-link", link.findingId, node.source);
      annotate("finding", node.id, why, node.source, null, "not-applicable", "not-applicable", link.findingId);
      links.add(`${link.nodeId}:${link.findingId}`);
      if (node.kind === "function") { functions.add(node.id); contracts.add(node.contractId); }
      else if (["contract", "interface", "library"].includes(node.kind)) contracts.add(node.id);
    }
    addMetric("contractsWithFindings", contracts.size); addMetric("functionsWithFindings", functions.size);
    addMetric("attachedFindingRefs", links.size);
  }
  if (artifact.graph.warnings.length) warn("graph-analysis-partial", artifact.graph.warnings.length);
  const sortedReasons = (items: z.infer<typeof reasonSchema>[]) => items.sort((a, b) => reasonKey(a).localeCompare(reasonKey(b)));
  const allNodes = [...nodes].sort(([a], [b]) => a.localeCompare(b)).map(([id, reasons]) => ({ id, reasons: sortedReasons(reasons) }));
  const edgeById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const allEdges = [...edges].sort(([a], [b]) => a.localeCompare(b)).map(([id, reasons]) => {
    const edge = edgeById.get(id)!;
    const low = edge.reasons.find((item) => item.startsWith("low-level-"))?.slice("low-level-".length);
    const callType = low && ["call", "staticcall", "delegatecall", "callcode"].includes(low) ?
      low as "call" | "staticcall" | "delegatecall" | "callcode" : edge.kind === "external-call" ? "high-level" : "not-applicable";
    const target = functionOwner(edge.to);
    const targetContext = edge.kind !== "calls" && edge.kind !== "external-call" && edge.kind !== "delegates" ?
      "not-applicable" : target?.kind === "external-actor" ? "unresolved" :
        target?.kind === "external-protocol" ? "external-contract" :
          target && "repositoryClassification" in target && target.repositoryClassification.effective === "dependency" ?
            "dependency" : target ? "internal-protocol" : "unresolved";
    return { id, reasons: sortedReasons(reasons), callType, targetContext };
  });
  annotations.sort((a, b) => a.id.localeCompare(b.id));
  const clipped = allNodes.length > SECURITY_VIEW_LIMITS.nodes || allEdges.length > SECURITY_VIEW_LIMITS.edges ||
    annotations.length > SECURITY_VIEW_LIMITS.annotations;
  if (clipped) warn("view-truncated");
  const chosenEdges = allEdges.slice(0, SECURITY_VIEW_LIMITS.edges);
  const required = new Set<string>(chosenEdges.flatMap((item) => {
    const edge = edgeById.get(item.id)!; return [edge.from, edge.to];
  }));
  const chosenNodes = [...allNodes.filter((item) => required.has(item.id)),
    ...allNodes.filter((item) => !required.has(item.id))].slice(0, SECURITY_VIEW_LIMITS.nodes)
    .sort((a, b) => a.id.localeCompare(b.id));
  const chosenIds = new Set(chosenNodes.map((item) => item.id));
  const finalEdges = chosenEdges.filter((item) => {
    const edge = edgeById.get(item.id)!; return chosenIds.has(edge.from) && chosenIds.has(edge.to);
  });
  const finalEdgeIds = new Set(finalEdges.map((item) => item.id));
  const finalAnnotations = annotations.filter((item) => chosenIds.has(item.nodeId) &&
    (!item.graphEdgeId || finalEdgeIds.has(item.graphEdgeId))).slice(0, SECURITY_VIEW_LIMITS.annotations);
  const provided = new Map(findingMetadataInput.map((item) => [item.id, findingMetadataSchema.parse(item)]));
  const linked = new Set(finalAnnotations.flatMap((item) => item.findingId ? [item.findingId] : []));
  const findingMetadata = [...linked].sort().flatMap((id) => provided.has(id) ? [provided.get(id)!] : [])
    .slice(0, SECURITY_VIEW_LIMITS.findingMetadata);
  if (linked.size > SECURITY_VIEW_LIMITS.findingMetadata) warn("finding-metadata-truncated", linked.size - SECURITY_VIEW_LIMITS.findingMetadata);
  const summary = { nodeCount: chosenNodes.length, edgeCount: finalEdges.length,
    annotationCount: finalAnnotations.length, metrics: [...metrics].sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => metricKey(key, value)) };
  const content = { schema: SECURITY_VIEW_SCHEMA, derivationVersion: SECURITY_VIEW_DERIVATION_VERSION,
    id: `sv:${hash(SECURITY_VIEW_SCHEMA, [artifact.contentSha256, viewType, SECURITY_VIEW_DERIVATION_VERSION])}`,
    scanId: graph.scanId, protocolGraphId: graph.id, graphContentSha256: artifact.contentSha256,
    viewType, nodes: chosenNodes, edges: finalEdges, annotations: finalAnnotations, findingMetadata,
    summary, warnings: [...warnings].filter(([, count]) => count > 0).sort(([a], [b]) => a.localeCompare(b))
      .map(([code, count]) => ({ code: code as typeof warningCodes[number], count })),
    provenance: { graphSchema: graph.schema, staticArtifactSchema: artifact.schema,
      repositoryMapId: artifact.repositoryMapId, extractorVersion: graph.extractorVersion } };
  return validateSecurityView(artifact, { ...content, contentSha256: hash(SECURITY_VIEW_SCHEMA, content) });
}

export function deriveSecurityView(artifact: StaticProtocolGraphArtifact, viewType: SecurityViewType,
  findingMetadata: readonly SecurityFindingMetadata[] = []): SecurityViewResult {
  return deriveValidatedSecurityView(validateStaticProtocolGraphArtifact(artifact), viewType, findingMetadata);
}

export function deriveAllSecurityViews(artifact: StaticProtocolGraphArtifact,
  findingMetadata: readonly SecurityFindingMetadata[] = []): SecurityViewResult[] {
  const validated = validateStaticProtocolGraphArtifact(artifact);
  return securityViewTypes.map((view) => deriveValidatedSecurityView(validated, view, findingMetadata));
}

export function validateSecurityView(artifact: StaticProtocolGraphArtifact, input: unknown): SecurityViewResult {
  const result = securityViewSchema.parse(input), byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const edges = new Map(artifact.graph.edges.map((edge) => [edge.id, edge]));
  const selected = new Set(result.nodes.map((item) => item.id)), selectedEdges = new Set(result.edges.map((item) => item.id));
  const linkedFindings = new Set(artifact.findingLinks.map((item) => item.findingId));
  const linkedPairs = new Set(artifact.findingLinks.map((item) => `${item.findingId}:${item.nodeId}`));
  const functionFacts = new Set(artifact.functionFacts.map((item) => item.functionId));
  const syntaxFacts = new Set((artifact.functionSyntax ?? []).flatMap((item) => item.operations.map((operation) =>
    `${item.functionId}:${operation.astNodeId}`)));
  const allReasons = [...result.nodes.flatMap((item) => item.reasons), ...result.edges.flatMap((item) => item.reasons),
    ...result.annotations.flatMap((item) => item.reasons)];
  const { contentSha256, ...content } = result;
  if (result.scanId !== artifact.graph.scanId || result.protocolGraphId !== artifact.graph.id ||
    result.graphContentSha256 !== artifact.contentSha256 ||
    result.provenance.repositoryMapId !== artifact.repositoryMapId ||
    result.provenance.extractorVersion !== artifact.graph.extractorVersion ||
    result.id !== `sv:${hash(SECURITY_VIEW_SCHEMA, [artifact.contentSha256, result.viewType, result.derivationVersion])}` ||
    contentSha256 !== hash(SECURITY_VIEW_SCHEMA, content) ||
    selected.size !== result.nodes.length || selectedEdges.size !== result.edges.length ||
    new Set(result.annotations.map((item) => item.id)).size !== result.annotations.length ||
    new Set(result.findingMetadata.map((item) => item.id)).size !== result.findingMetadata.length ||
    new Set(result.summary.metrics.map((item) => item.key)).size !== result.summary.metrics.length ||
    new Set(result.warnings.map((item) => item.code)).size !== result.warnings.length ||
    result.nodes.some((item) => !byId.has(item.id)) ||
    result.edges.some((item) => !edges.has(item.id) || !selected.has(edges.get(item.id)!.from) ||
      !selected.has(edges.get(item.id)!.to)) ||
    result.annotations.some((item) => !selected.has(item.nodeId) ||
      item.graphEdgeId !== null && !selectedEdges.has(item.graphEdgeId) ||
      item.findingId !== null && !linkedPairs.has(`${item.findingId}:${item.nodeId}`)) ||
    result.findingMetadata.some((item) => !linkedFindings.has(item.id)) ||
    allReasons.some((item) => item.explanationKey !== item.code ||
      item.sourceKind === "graph-node" && !byId.has(item.sourceId) ||
      item.sourceKind === "node-characteristic" && !byId.has(item.sourceId) ||
      item.sourceKind === "graph-edge" && !edges.has(item.sourceId) ||
      item.sourceKind === "function-fact" && !functionFacts.has(item.sourceId) ||
      item.sourceKind === "function-syntax" && !syntaxFacts.has(item.sourceId) ||
      item.sourceKind === "finding-link" && !linkedFindings.has(item.sourceId)) ||
    result.summary.nodeCount !== result.nodes.length || result.summary.edgeCount !== result.edges.length ||
    result.summary.annotationCount !== result.annotations.length)
    throw Error("security_view_integrity_invalid");
  return result;
}
