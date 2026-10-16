import { createHash } from "node:crypto";
import { z } from "zod";
import { protocolSourceLocationSchema, repositoryClasses, type ProtocolGraphNode,
  type ProtocolSourceLocation } from "./protocol-graph";
import { validateStaticProtocolGraphArtifact, type StaticProtocolGraphArtifact } from "./static-protocol-graph";
import { validateRepositoryMap, type RepositoryMap } from "./repository-map";
import { deriveAllSecurityViews, securityViewTypes, validateSecurityView,
  type SecurityViewResult, type SecurityViewType } from "./security-view";
import { AUDIT_PRIORITY_CATALOG_VERSION, AUDIT_PRIORITY_RULESET_VERSION, auditConcepts,
  auditFactorRules, type AuditFactorId } from "./audit-priority-catalog";

export { AUDIT_PRIORITY_CATALOG_VERSION, AUDIT_PRIORITY_RULESET_VERSION, auditConcepts, auditFactorRules } from "./audit-priority-catalog";
export const AUDIT_PRIORITY_SCHEMA = "contracthunter-audit-priority-v1" as const;
export const AUDIT_PRIORITY_DERIVATION_VERSION = "contracthunter-audit-priority-deriver-v1" as const;
export const AUDIT_PRIORITY_LIMITS = { contracts: 50, functionsPerContract: 10, factors: 24,
  evidencePerFactor: 8, checklist: 12, warnings: 32, views: 7 } as const;
export const AUDIT_PRIORITY_MEANING = "A higher Audit Priority Score means more known security-relevant characteristics worth manual review. It does not mean a vulnerability is more likely." as const;

const nodeId = z.string().regex(/^pn:[a-f0-9]{64}$/), sha = z.string().regex(/^[a-f0-9]{64}$/);
const evidenceKind = z.enum(["graph-node", "graph-edge", "security-annotation", "function-fact",
  "function-syntax", "finding-link", "classification"]);
const evidenceRef = z.object({ kind: evidenceKind, id: z.string().min(1).max(180),
  source: protocolSourceLocationSchema.nullable() }).strict();
const factor = z.object({ id: z.enum(Object.keys(auditFactorRules) as [AuditFactorId, ...AuditFactorId[]]),
  count: z.number().int().positive(), potentialPoints: z.number().int().nonnegative().max(100),
  points: z.number().int().nonnegative().max(100), explanationKey: z.enum(Object.keys(auditConcepts) as
    [keyof typeof auditConcepts, ...(keyof typeof auditConcepts)[]]),
  evidence: z.array(evidenceRef).min(1).max(AUDIT_PRIORITY_LIMITS.evidencePerFactor) }).strict();
const checklist = z.object({ conceptKey: factor.shape.explanationKey, prompt: z.string().min(1).max(200),
  factorIds: z.array(factor.shape.id).min(1).max(AUDIT_PRIORITY_LIMITS.factors),
  findingIds: z.array(z.string().uuid()).max(AUDIT_PRIORITY_LIMITS.evidencePerFactor) }).strict();
const rankedFunction = z.object({ id: nodeId, signature: z.string().max(256), source: protocolSourceLocationSchema,
  score: z.number().int().min(0).max(100), uncappedScore: z.number().int().nonnegative(),
  factors: z.array(factor).max(AUDIT_PRIORITY_LIMITS.factors), findingCount: z.number().int().nonnegative(),
  checklist: z.array(checklist).max(AUDIT_PRIORITY_LIMITS.checklist) }).strict();
const rankedContract = z.object({ id: nodeId, name: z.string().max(200), qualifiedName: z.string().max(1_200),
  source: protocolSourceLocationSchema, classification: z.enum(repositoryClasses), score: z.number().int().min(0).max(100),
  uncappedScore: z.number().int().nonnegative(), factors: z.array(factor).max(AUDIT_PRIORITY_LIMITS.factors),
  findingCount: z.number().int().nonnegative(), securityViews: z.array(z.enum(securityViewTypes)).max(7),
  recommendedFunctions: z.array(rankedFunction).max(AUDIT_PRIORITY_LIMITS.functionsPerContract),
  checklist: z.array(checklist).max(AUDIT_PRIORITY_LIMITS.checklist) }).strict();
const warningCodes = ["repository-map-unavailable", "graph-analysis-partial", "contracts-without-source-omitted",
  "functions-without-source-omitted", "oracle-evidence-unavailable", "access-control-extraction-unavailable",
  "call-target-unresolved", "syntax-facts-unavailable", "security-view-truncated", "output-truncated"] as const;
export const auditPrioritySchema = z.object({ schema: z.literal(AUDIT_PRIORITY_SCHEMA),
  derivationVersion: z.literal(AUDIT_PRIORITY_DERIVATION_VERSION), rulesetVersion: z.literal(AUDIT_PRIORITY_RULESET_VERSION),
  explanationCatalogVersion: z.literal(AUDIT_PRIORITY_CATALOG_VERSION), scoreMeaning: z.literal(AUDIT_PRIORITY_MEANING),
  scanId: z.string().uuid(), protocolGraphId: z.string().regex(/^pg:[a-f0-9]{64}$/), graphContentSha256: sha,
  repositoryMapId: z.string().regex(/^rm:[a-f0-9]{64}$/),
  viewContentIds: z.array(z.object({ viewType: z.enum(securityViewTypes), id: z.string().regex(/^sv:[a-f0-9]{64}$/),
    contentSha256: sha }).strict()).length(AUDIT_PRIORITY_LIMITS.views),
  projectOverview: z.object({ solidityFiles: z.number().int().nonnegative().nullable(),
    filesByClass: z.array(z.object({ classification: z.enum(repositoryClasses), count: z.number().int().nonnegative() }).strict()).max(repositoryClasses.length),
    contracts: z.number().int().nonnegative(), coreContracts: z.number().int().nonnegative(),
    peripheryContracts: z.number().int().nonnegative(), interfaces: z.number().int().nonnegative(),
    libraries: z.number().int().nonnegative(), externalEntryPoints: z.number().int().nonnegative(),
    externalCalls: z.number().int().nonnegative(), unresolvedCalls: z.number().int().nonnegative(),
    tokenTransferLikeOperations: z.number().int().nonnegative(), nativeValueTransfers: z.number().int().nonnegative(),
    proxyRelationships: z.number().int().nonnegative(), controlRelationships: z.number().int().nonnegative(),
    contractsWithFindings: z.number().int().nonnegative() }).strict(),
  totalRankableContracts: z.number().int().nonnegative(), rankedContracts: z.array(rankedContract).max(AUDIT_PRIORITY_LIMITS.contracts),
  analysisStatus: z.enum(["complete", "partial"]), warnings: z.array(z.object({ code: z.enum(warningCodes),
    count: z.number().int().positive() }).strict()).max(AUDIT_PRIORITY_LIMITS.warnings),
  contentSha256: sha }).strict();
export type AuditPriorityResult = z.infer<typeof auditPrioritySchema>;
export type AuditPriorityFactor = AuditPriorityResult["rankedContracts"][number]["factors"][number];
type EvidenceRef = z.infer<typeof evidenceRef>;
type FactorSeed = { count: number; evidence: EvidenceRef[]; seen: Set<string> };
type FactorBag = Map<AuditFactorId, FactorSeed>;
type ContractNode = Extract<ProtocolGraphNode, { kind: "contract" }>;
type FunctionNode = Extract<ProtocolGraphNode, { kind: "function" }>;

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function digest(value: unknown): string { return createHash("sha256").update(AUDIT_PRIORITY_SCHEMA).update("\0")
  .update(canonical(value)).digest("hex"); }
export function auditPriorityContentHash(value: Omit<AuditPriorityResult, "contentSha256">): string {
  return digest(value);
}
const ref = (kind: EvidenceRef["kind"], id: string, source: ProtocolSourceLocation | null): EvidenceRef =>
  ({ kind, id, source });
function add(bag: FactorBag, id: AuditFactorId, evidence: EvidenceRef, uniqueness = evidence.id): void {
  const seed = bag.get(id) ?? { count: 0, evidence: [], seen: new Set<string>() };
  if (seed.seen.has(uniqueness)) return;
  seed.seen.add(uniqueness); seed.count++;
  if (seed.evidence.length < AUDIT_PRIORITY_LIMITS.evidencePerFactor) seed.evidence.push(evidence);
  bag.set(id, seed);
}
function points(id: AuditFactorId, count: number): number {
  const max = auditFactorRules[id].max;
  if (["external-entry-points", "external-call", "unresolved-external-call", "state-writing", "connectivity", "finding-linked"].includes(id))
    return count === 1 ? Math.max(1, Math.ceil(max / 2)) : count <= 5 ? Math.max(1, max - 2) : max;
  return max;
}
function finalizeFactors(bag: FactorBag): { score: number; uncappedScore: number; factors: AuditPriorityFactor[] } {
  const ranked = [...bag].map(([id, seed]) => ({ id, count: seed.count, potentialPoints: points(id, seed.count),
    points: 0, explanationKey: auditFactorRules[id].concept,
    evidence: [...seed.evidence].sort((a, b) => a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id)) }))
    .sort((a, b) => b.potentialPoints - a.potentialPoints || a.id.localeCompare(b.id));
  let remaining = 100;
  for (const item of ranked) { item.points = Math.min(remaining, item.potentialPoints); remaining -= item.points; }
  return { score: 100 - remaining, uncappedScore: ranked.reduce((sum, item) => sum + item.potentialPoints, 0),
    factors: ranked };
}
function checklistFor(factors: readonly AuditPriorityFactor[]): AuditPriorityResult["rankedContracts"][number]["checklist"] {
  const items = new Map<string, { conceptKey: AuditPriorityFactor["explanationKey"]; prompt: string;
    factorIds: AuditFactorId[]; findingIds: string[] }>();
  for (const factor of factors) for (const prompt of auditConcepts[factor.explanationKey].inspect) {
    const key = `${factor.explanationKey}:${prompt}`, existing = items.get(key);
    if (existing) existing.factorIds.push(factor.id);
    else items.set(key, { conceptKey: factor.explanationKey, prompt, factorIds: [factor.id],
      findingIds: factor.id === "finding-linked" ? [...new Set(factor.evidence.filter((item) => item.kind === "finding-link")
        .map((item) => item.id.split(":pn:")[0]))].sort().slice(0, AUDIT_PRIORITY_LIMITS.evidencePerFactor) : [] });
  }
  return [...items.values()].slice(0, AUDIT_PRIORITY_LIMITS.checklist);
}
const ownerId = (node: ProtocolGraphNode | undefined): string | null =>
  node?.kind === "function" ? node.contractId : node?.id ?? null;
const metric = (view: SecurityViewResult, key: string) => view.summary.metrics.find((item) => item.key === key)?.value ?? 0;

/** Evidence-backed static review ordering. Scores are interest signals, never vulnerability probabilities. */
export function deriveAuditPriority(artifactInput: StaticProtocolGraphArtifact,
  viewInputs: readonly SecurityViewResult[], repositoryMapInput: RepositoryMap | null = null,
  options: { topContracts?: number; functionsPerContract?: number } = {}): AuditPriorityResult {
  const artifact = validateStaticProtocolGraphArtifact(artifactInput), graph = artifact.graph;
  const map = repositoryMapInput ? validateRepositoryMap(repositoryMapInput) : null;
  if (map && (map.id !== artifact.repositoryMapId || map.scanId !== graph.scanId ||
    map.resolvedCommit !== graph.resolvedCommit)) throw Error("audit_priority_repository_map_identity_invalid");
  if (viewInputs.length !== securityViewTypes.length || new Set(viewInputs.map((view) => view.viewType)).size !== securityViewTypes.length)
    throw Error("audit_priority_views_incomplete");
  const views = new Map<SecurityViewType, SecurityViewResult>();
  for (const input of viewInputs) views.set(input.viewType, validateSecurityView(artifact, input));
  if (securityViewTypes.some((kind) => !views.has(kind))) throw Error("audit_priority_views_incomplete");
  const topContracts = options.topContracts ?? 10, functionsPerContract = options.functionsPerContract ?? 5;
  if (!Number.isInteger(topContracts) || topContracts < 1 || topContracts > AUDIT_PRIORITY_LIMITS.contracts ||
    !Number.isInteger(functionsPerContract) || functionsPerContract < 1 ||
    functionsPerContract > AUDIT_PRIORITY_LIMITS.functionsPerContract) throw Error("audit_priority_presentation_bounds_invalid");
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const contracts = graph.nodes.filter((node): node is ContractNode => node.kind === "contract");
  const functions = graph.nodes.filter((node): node is FunctionNode => node.kind === "function");
  const contractBags = new Map(contracts.map((node) => [node.id, new Map<AuditFactorId, FactorSeed>()]));
  const functionBags = new Map(functions.map((node) => [node.id, new Map<AuditFactorId, FactorSeed>()]));
  const addFunction = (functionId: string, factorId: AuditFactorId, evidence: EvidenceRef, uniqueness?: string) => {
    const fn = byId.get(functionId);
    if (fn?.kind !== "function") return;
    const functionBag = functionBags.get(fn.id), contractBag = contractBags.get(fn.contractId);
    if (functionBag) add(functionBag, factorId, evidence, uniqueness);
    if (contractBag) add(contractBag, factorId, evidence, uniqueness);
  };
  const addContract = (id: string, factorId: AuditFactorId, evidence: EvidenceRef, uniqueness?: string) => {
    const bag = contractBags.get(id); if (bag) add(bag, factorId, evidence, uniqueness);
  };
  const warnings = new Map<AuditPriorityResult["warnings"][number]["code"], number>();
  const warn = (code: AuditPriorityResult["warnings"][number]["code"], count = 1) =>
    warnings.set(code, (warnings.get(code) ?? 0) + count);
  if (!map) warn("repository-map-unavailable");
  if (graph.warnings.length) warn("graph-analysis-partial", graph.warnings.length);
  const sourceMissing = contracts.filter((node) => !node.source).length;
  if (sourceMissing) warn("contracts-without-source-omitted", sourceMissing);
  const functionMissing = functions.filter((node) => !node.source).length;
  if (functionMissing) warn("functions-without-source-omitted", functionMissing);
  for (const view of views.values()) for (const warning of view.warnings) {
    if (["oracle-evidence-unavailable", "access-control-extraction-unavailable", "call-target-unresolved",
      "syntax-facts-unavailable"].includes(warning.code)) warn(warning.code as AuditPriorityResult["warnings"][number]["code"], warning.count);
    if (warning.code === "view-truncated") warn("security-view-truncated", warning.count);
  }

  for (const contract of contracts) if (contract.repositoryClassification.effective === "core")
    addContract(contract.id, "core-protocol", ref("classification", contract.id, contract.source));
  for (const fn of functions) {
    if (fn.entryPoint === "yes") addFunction(fn.id, "external-entry-points", ref("graph-node", fn.id, fn.source));
    if (fn.mutability === "payable") addFunction(fn.id, "payable", ref("graph-node", fn.id, fn.source));
  }
  for (const fact of artifact.functionFacts) for (const write of fact.stateWrites)
    addFunction(fact.functionId, "state-writing", ref("function-fact", fact.functionId, write.source),
      `${write.contractId}:${write.declarationId}:${write.source.startByte ?? write.source.startLine}`);
  const money = views.get("money-flow")!;
  for (const item of money.annotations) if (item.kind === "token-transfer-like" || item.kind === "native-value-transfer")
    addFunction(item.nodeId, item.kind === "token-transfer-like" ? "token-transfer" : "native-value-transfer",
      ref("security-annotation", item.id, item.source));
  const external = views.get("external-calls")!;
  const edgeById = new Map(graph.edges.map((edge) => [edge.id, edge]));
  const externalSites = new Map<string, ProtocolSourceLocation[]>();
  for (const item of external.edges) {
    const edge = edgeById.get(item.id)!;
    const functionId = edge.fromFunctionId ?? (byId.get(edge.from)?.kind === "function" ? edge.from : null);
    if (!functionId) continue;
    const evidence = ref("graph-edge", edge.id, edge.source);
    addFunction(functionId, "external-call", evidence);
    if (item.callType !== "high-level" && item.callType !== "not-applicable") addFunction(functionId, "low-level-call", evidence);
    if (item.callType === "delegatecall") addFunction(functionId, "delegatecall", evidence);
    if (item.targetContext === "unresolved") addFunction(functionId, "unresolved-external-call", evidence);
    if (edge.source) externalSites.set(functionId, [...(externalSites.get(functionId) ?? []), edge.source]);
  }
  for (const item of external.annotations) if (item.kind === "unresolved-call")
    addFunction(item.nodeId, "unresolved-external-call", ref("security-annotation", item.id, item.source),
      item.graphEdgeId ?? item.id);
  for (const fact of artifact.functionFacts) if (fact.stateWrites.some((write) => externalSites.get(fact.functionId)?.some((site) =>
    write.source.startByte !== null && site.startByte !== null && write.source.startByte > site.startByte))) {
    const write = fact.stateWrites.find((item) => externalSites.get(fact.functionId)?.some((site) =>
      item.source.startByte !== null && site.startByte !== null && item.source.startByte > site.startByte))!;
    addFunction(fact.functionId, "write-after-external-call-source-order",
      ref("function-fact", fact.functionId, write.source));
  }
  const permissions = views.get("permissions")!;
  for (const item of permissions.edges) {
    const edge = edgeById.get(item.id)!;
    const to = byId.get(edge.toFunctionId ?? edge.to);
    if (to?.kind !== "function") continue;
    const code = item.reasons.some((reason) => reason.code === "owner-controlled") ? "owner-controlled" : "role-controlled";
    addFunction(to.id, code, ref("graph-edge", edge.id, edge.source));
  }
  for (const item of permissions.nodes) if (item.reasons.some((reason) => reason.code === "privileged-operation")) {
    const node = byId.get(item.id);
    if (node?.kind === "function") addFunction(node.id, "privileged-operation", ref("graph-node", node.id, node.source));
  }
  const oracle = views.get("oracle-flow")!;
  for (const item of oracle.annotations) if (item.kind === "oracle-consumer")
    addFunction(item.nodeId, "oracle-dependent", ref("security-annotation", item.id, item.source));
  const upgrade = views.get("upgradeability")!;
  for (const item of upgrade.nodes) {
    const node = byId.get(item.id);
    if (!node) continue;
    const owner = ownerId(node);
    if (!owner) continue;
    for (const reason of item.reasons) {
      if (reason.code === "proxy") addContract(owner, "proxy", ref("graph-node", node.id, reason.source));
      if (reason.code === "upgradeable") addContract(owner, "upgradeable", ref("graph-node", node.id, reason.source));
    }
  }
  for (const item of upgrade.edges) if (item.reasons.some((reason) => reason.code === "upgrade-authority")) {
    const edge = edgeById.get(item.id)!;
    const target = byId.get(edge.toFunctionId ?? edge.to);
    if (target?.kind === "function") addFunction(target.id, "privileged-operation", ref("graph-edge", edge.id, edge.source));
  }
  const surface = views.get("attack-surface")!;
  for (const item of surface.annotations) {
    if (item.kind === "assembly") addFunction(item.nodeId, "assembly", ref("security-annotation", item.id, item.source));
    if (item.kind === "callback") addFunction(item.nodeId, "callback", ref("security-annotation", item.id, item.source));
  }
  const findingCount = new Map<string, Set<string>>();
  for (const link of artifact.findingLinks) {
    const node = byId.get(link.nodeId)!, contractId = ownerId(node);
    if (!contractId) continue;
    const key = `${link.findingId}:${link.nodeId}`, evidence = ref("finding-link", key, node.source);
    if (node.kind === "function") addFunction(node.id, "finding-linked", evidence, link.findingId);
    else addContract(contractId, "finding-linked", evidence, link.findingId);
    const ids = findingCount.get(contractId) ?? new Set<string>(); ids.add(link.findingId); findingCount.set(contractId, ids);
  }
  const neighbors = new Map<string, Set<string>>();
  for (const edge of graph.edges) if (["calls", "external-call", "delegates"].includes(edge.kind)) {
    const from = ownerId(byId.get(edge.from)), to = ownerId(byId.get(edge.to));
    if (!from || !to || from === to) continue;
    for (const [current, other] of [[from, to], [to, from]]) {
      if (!contractBags.has(current)) continue;
      const prior = neighbors.get(current) ?? new Set<string>();
      if (prior.has(other)) continue;
      prior.add(other); neighbors.set(current, prior);
      addContract(current, "connectivity", ref("graph-edge", edge.id, edge.source), other);
    }
  }
  const membership = new Map<string, Set<SecurityViewType>>();
  for (const [type, view] of views) for (const item of view.nodes) {
    const contractId = ownerId(byId.get(item.id));
    if (!contractId || !contractBags.has(contractId)) continue;
    const set = membership.get(contractId) ?? new Set<SecurityViewType>(); set.add(type); membership.set(contractId, set);
  }
  const functionFindings = new Map<string, Set<string>>();
  for (const link of artifact.findingLinks) if (byId.get(link.nodeId)?.kind === "function") {
    const set = functionFindings.get(link.nodeId) ?? new Set<string>(); set.add(link.findingId); functionFindings.set(link.nodeId, set);
  }
  const functionsByContract = new Map<string, FunctionNode[]>();
  for (const fn of functions) if (fn.source) {
    const list = functionsByContract.get(fn.contractId) ?? []; list.push(fn); functionsByContract.set(fn.contractId, list);
  }
  const compareFunction = (a: AuditPriorityResult["rankedContracts"][number]["recommendedFunctions"][number],
    b: typeof a) => b.score - a.score || a.signature.localeCompare(b.signature) || a.id.localeCompare(b.id);
  const ranked = contracts.filter((node): node is ContractNode & { source: ProtocolSourceLocation } => !!node.source)
    .map((node) => {
      const calculated = finalizeFactors(contractBags.get(node.id)!);
      const recommendedFunctions = (functionsByContract.get(node.id) ?? []).map((fn) => {
        const result = finalizeFactors(functionBags.get(fn.id)!);
        return { id: fn.id, signature: fn.signature, source: fn.source!, ...result,
          findingCount: functionFindings.get(fn.id)?.size ?? 0, checklist: checklistFor(result.factors) };
      }).sort(compareFunction).slice(0, functionsPerContract);
      return { id: node.id, name: node.name, qualifiedName: node.qualifiedName, source: node.source,
        classification: node.repositoryClassification.effective, ...calculated,
        findingCount: findingCount.get(node.id)?.size ?? 0,
        securityViews: [...(membership.get(node.id) ?? [])].sort(), recommendedFunctions,
        checklist: checklistFor(calculated.factors) };
    }).sort((a, b) => b.score - a.score || Number(b.classification === "core") - Number(a.classification === "core") ||
      a.source.sourceUnitName.localeCompare(b.source.sourceUnitName) || a.qualifiedName.localeCompare(b.qualifiedName) ||
      a.id.localeCompare(b.id));
  if (ranked.length > topContracts) warn("output-truncated", ranked.length - topContracts);
  const moneyView = views.get("money-flow")!, callsView = views.get("external-calls")!, findingsView = views.get("findings")!;
  const filesByClass = map ? repositoryClasses.map((classification) => ({ classification,
    count: map.summary.classes[classification] ?? 0 })) : [];
  const content = { schema: AUDIT_PRIORITY_SCHEMA, derivationVersion: AUDIT_PRIORITY_DERIVATION_VERSION,
    rulesetVersion: AUDIT_PRIORITY_RULESET_VERSION, explanationCatalogVersion: AUDIT_PRIORITY_CATALOG_VERSION,
    scoreMeaning: AUDIT_PRIORITY_MEANING, scanId: graph.scanId, protocolGraphId: graph.id,
    graphContentSha256: artifact.contentSha256, repositoryMapId: artifact.repositoryMapId,
    viewContentIds: securityViewTypes.map((viewType) => ({ viewType, id: views.get(viewType)!.id,
      contentSha256: views.get(viewType)!.contentSha256 })),
    projectOverview: { solidityFiles: map?.summary.solidityFiles ?? null, filesByClass,
      contracts: contracts.length, coreContracts: contracts.filter((node) => node.repositoryClassification.effective === "core").length,
      peripheryContracts: contracts.filter((node) => node.repositoryClassification.effective === "periphery").length,
      interfaces: graph.nodes.filter((node) => node.kind === "interface").length,
      libraries: graph.nodes.filter((node) => node.kind === "library").length,
      externalEntryPoints: functions.filter((node) => node.entryPoint === "yes").length,
      externalCalls: metric(callsView, "resolvedCalls") + metric(callsView, "unresolvedCalls"),
      unresolvedCalls: metric(callsView, "unresolvedCalls"), tokenTransferLikeOperations: metric(moneyView, "tokenOperations"),
      nativeValueTransfers: metric(moneyView, "nativeTransfers"),
      proxyRelationships: metric(views.get("upgradeability")!, "proxies"),
      controlRelationships: graph.edges.filter((edge) => edge.kind === "controls").length,
      contractsWithFindings: metric(findingsView, "contractsWithFindings") },
    totalRankableContracts: ranked.length, rankedContracts: ranked.slice(0, topContracts),
    analysisStatus: warnings.size ? "partial" as const : "complete" as const,
    warnings: [...warnings].sort(([a], [b]) => a.localeCompare(b)).map(([code, count]) => ({ code, count })) };
  return validateAuditPriority(artifact, [...views.values()], { ...content, contentSha256: auditPriorityContentHash(content) });
}

export function deriveAuditPriorityFromArtifact(artifact: StaticProtocolGraphArtifact,
  repositoryMap: RepositoryMap | null = null): AuditPriorityResult {
  return deriveAuditPriority(artifact, deriveAllSecurityViews(artifact), repositoryMap);
}

export function validateAuditPriority(artifact: StaticProtocolGraphArtifact,
  views: readonly SecurityViewResult[], input: unknown): AuditPriorityResult {
  const result = auditPrioritySchema.parse(input), { contentSha256, ...content } = result;
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const graphEdges = new Set(artifact.graph.edges.map((edge) => edge.id));
  const edgesById = new Map(artifact.graph.edges.map((edge) => [edge.id, edge]));
  const annotations = new Map(views.flatMap((view) => view.annotations.map((item) => [item.id, item] as const)));
  const functionFacts = new Set(artifact.functionFacts.map((item) => item.functionId));
  const factsById = new Map(artifact.functionFacts.map((item) => [item.functionId, item]));
  const syntaxFacts = new Set((artifact.functionSyntax ?? []).flatMap((item) => item.operations.map((op) => `${item.functionId}:${op.astNodeId}`)));
  const findingLinks = new Set(artifact.findingLinks.map((item) => `${item.findingId}:${item.nodeId}`));
  const sameSource = (a: ProtocolSourceLocation | null, b: ProtocolSourceLocation | null) =>
    a === null && b === null || !!a && !!b && a.sourceUnitName === b.sourceUnitName &&
    a.startByte === b.startByte && a.startLine === b.startLine;
  const evidenceValid = (evidence: EvidenceRef) => {
    if (evidence.kind === "graph-node" || evidence.kind === "classification") {
      const node = byId.get(evidence.id);
      return !!node && (evidence.kind !== "classification" || node.kind === "contract") &&
        (!evidence.source || evidence.source.sourceUnitName === node.source?.sourceUnitName);
    }
    if (evidence.kind === "graph-edge") {
      const edge = edgesById.get(evidence.id);
      return graphEdges.has(evidence.id) && !!edge && (!evidence.source || sameSource(evidence.source, edge.source));
    }
    if (evidence.kind === "security-annotation") return annotations.has(evidence.id) &&
      sameSource(evidence.source, annotations.get(evidence.id)!.source);
    if (evidence.kind === "function-fact") return functionFacts.has(evidence.id) &&
      !!evidence.source && !!factsById.get(evidence.id)?.stateWrites.some((item) => sameSource(item.source, evidence.source));
    if (evidence.kind === "function-syntax") return syntaxFacts.has(evidence.id);
    if (evidence.kind === "finding-link") {
      const [findingId, nodeIdValue] = evidence.id.split(":pn:");
      const node = byId.get(nodeIdValue ? `pn:${nodeIdValue}` : "");
      return findingLinks.has(evidence.id) && !!findingId && !!node && sameSource(evidence.source, node.source);
    }
    return false;
  };
  const evidenceBelongs = (evidence: EvidenceRef, itemId: string) => {
    const isFunction = byId.get(itemId)?.kind === "function";
    const related = (nodeIdValue: string) => isFunction ? nodeIdValue === itemId :
      ownerId(byId.get(nodeIdValue)) === itemId;
    if (evidence.kind === "graph-node" || evidence.kind === "classification") return related(evidence.id);
    if (evidence.kind === "function-fact" || evidence.kind === "function-syntax")
      return related(evidence.id.split(":").slice(0, 2).join(":"));
    if (evidence.kind === "security-annotation") return related(annotations.get(evidence.id)?.nodeId ?? "");
    if (evidence.kind === "finding-link") {
      const nodeIdValue = evidence.id.split(":pn:")[1];
      return !!nodeIdValue && related(`pn:${nodeIdValue}`);
    }
    const edge = edgesById.get(evidence.id);
    return !!edge && [edge.from, edge.to, edge.fromFunctionId, edge.toFunctionId]
      .some((nodeIdValue) => !!nodeIdValue && related(nodeIdValue));
  };
  const items = result.rankedContracts.flatMap((contract) => [contract, ...contract.recommendedFunctions]);
  if (result.scanId !== artifact.graph.scanId || result.protocolGraphId !== artifact.graph.id ||
    result.graphContentSha256 !== artifact.contentSha256 || result.repositoryMapId !== artifact.repositoryMapId ||
    contentSha256 !== digest(content) || result.totalRankableContracts < result.rankedContracts.length ||
    result.viewContentIds.some((item, index) => item.viewType !== securityViewTypes[index] ||
      item.id !== views.find((view) => view.viewType === item.viewType)?.id ||
      item.contentSha256 !== views.find((view) => view.viewType === item.viewType)?.contentSha256) ||
    result.rankedContracts.some((contract) => byId.get(contract.id)?.kind !== "contract" ||
      !sameSource(contract.source, byId.get(contract.id)?.source ?? null) ||
      contract.recommendedFunctions.some((fn) => byId.get(fn.id)?.kind !== "function" ||
        (byId.get(fn.id) as FunctionNode).contractId !== contract.id ||
        !sameSource(fn.source, byId.get(fn.id)?.source ?? null))) ||
    items.some((item) => item.score !== item.factors.reduce((sum, factor) => sum + factor.points, 0) ||
      item.uncappedScore !== item.factors.reduce((sum, factor) => sum + factor.potentialPoints, 0) ||
      item.factors.some((factor) => factor.potentialPoints !== points(factor.id, factor.count) ||
        factor.explanationKey !== auditFactorRules[factor.id].concept || factor.points > factor.potentialPoints ||
        factor.evidence.some((evidence) => !evidenceValid(evidence) || !evidenceBelongs(evidence, item.id)))))
    throw Error("audit_priority_binding_invalid");
  return result;
}
