import { randomUUID } from "node:crypto";
import { buildEvidencePackage, canonicalEvidenceJson, evidenceArtifact, deriveScenarioImpact, deriveAllSecurityViews,
  impactPoCSourceHash, repositorySolidityPathSchema, containsSensitiveExportText,
  EVIDENCE_PACKAGE_LIMITS, type EvidenceArtifact, type EvidencePackage, type EvidenceSubject } from "@contracthunter/core";
import { finalizeEvidencePackage, getFinding, getInvestigation, getScan, getScanSource,
  getVulnerabilityHypothesis, insertEvidencePackage, listInvestigationFindings, readEvidencePackage,
  readImpactExecutionState, readImpactExecutionTraces, readImpactForkSession, readImpactPoCArtifact,
  readImpactPoCExecution, readImpactScenarioRevision, readScenarioReplayPlan, readScenarioReplayRun,
  readStaticProtocolGraph, type DatabaseClient } from "@contracthunter/db";
import { loadInvestigationPaths } from "./investigation-path-server";
import { loadImpactOverlay } from "./impact-overlay-server";
import { loadAssetFlow } from "./asset-flow-server";
import { readReplayResult } from "./impact-scenario-replay";

export type EvidencePackageSelection = { subjectType: "finding" | "investigation" | "hypothesis";
  subjectId: string; executionId: string | null; scenarioRevisionId: string | null; replayRunId: string | null };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function safeText(value: string): string { return containsSensitiveExportText(value) ? "[redacted sensitive text]" : value; }
function safeSource(value: string): boolean { return !containsSensitiveExportText(value); }
function subject(database: DatabaseClient, scanId: string, type: EvidencePackageSelection["subjectType"], id: string):
  { value: EvidenceSubject; findingIds: string[]; sourceKey: string | null; line: number | null } {
  if (type === "finding") {
    const row = getFinding(database, id);
    if (!row || row.scanId !== scanId) throw Error("evidence_subject_not_found");
    return { value: { type, id, title: safeText(row.title), status: row.status,
      existingSeverity: row.severity, existingConfidence: row.confidence }, findingIds: [id],
      sourceKey: row.filePath, line: row.startLine };
  }
  if (type === "investigation") {
    const row = getInvestigation(database, id);
    if (!row || row.scanId !== scanId) throw Error("evidence_subject_not_found");
    const findings = listInvestigationFindings(database, id).filter((item) => item.scanId === scanId);
    return { value: { type, id, title: safeText(row.title), status: row.status,
      existingSeverity: row.severity, existingConfidence: row.confidenceScore },
      findingIds: findings.map((item) => item.id), sourceKey: row.primaryFilePath, line: row.startLine };
  }
  const row = getVulnerabilityHypothesis(database, id);
  if (!row || row.scanId !== scanId) throw Error("evidence_subject_not_found");
  return { value: { type, id, title: safeText(row.title), status: row.status,
    existingSeverity: row.severity, existingConfidence: row.confidence }, findingIds: [],
    sourceKey: null, line: null };
}
function add(artifacts: EvidenceArtifact[], type: string, id: string, schemaVersion: string,
  status: EvidenceArtifact["status"], sourceContentHash: string | null, provenance: string[],
  recordCount: number | null, data: unknown) {
  artifacts.push(evidenceArtifact({ type, id, schemaVersion, status, sourceContentHash,
    provenance: [...new Set(provenance)].sort(), recordCount, data }));
}
function sourceExcerpt(bytes: Buffer, line: number | null) {
  const lines = new TextDecoder("utf-8", { fatal: true }).decode(bytes).split("\n");
  const first = Math.max(1, Math.min(lines.length, (line ?? 1) - 15));
  const selected = lines.slice(first - 1, first - 1 + EVIDENCE_PACKAGE_LIMITS.excerptLines);
  let excerpt = selected.join("\n");
  while (Buffer.byteLength(excerpt) > EVIDENCE_PACKAGE_LIMITS.excerptBytes && selected.length > 1) {
    selected.pop(); excerpt = selected.join("\n");
  }
  let truncatedLine = false;
  if (Buffer.byteLength(excerpt) > EVIDENCE_PACKAGE_LIMITS.excerptBytes) {
    const raw = Buffer.from(excerpt, "utf8");
    let end = EVIDENCE_PACKAGE_LIMITS.excerptBytes;
    while (end > 0) {
      try { excerpt = new TextDecoder("utf-8", { fatal: true }).decode(raw.subarray(0, end)); break; }
      catch { end--; }
    }
    truncatedLine = true;
  }
  return { startLine: first, endLine: first + selected.length - 1, excerpt, truncatedLine };
}
function traceProjection(trace: NonNullable<ReturnType<typeof readImpactExecutionTraces>>["traces"][number]) {
  if (!trace) return null;
  return { id: trace.id, schema: trace.schema, transactionOrdinal: trace.transactionOrdinal,
    transactionHash: trace.localTransactionHash, receipt: trace.receipt, stats: trace.stats,
    nodes: trace.nodes.map((node) => ({ ordinal: node.ordinal, parentOrdinal: node.parentOrdinal,
      depth: node.depth, callType: node.callType, from: node.from, to: node.to, valueWei: node.valueWei,
      outcome: node.outcome, selector: node.inputSelector, inputSha256: node.input.sha256,
      inputByteLength: node.input.byteLength, outputSha256: node.output?.sha256 ?? null,
      outputByteLength: node.output?.byteLength ?? null, revertKind: node.revertKind })),
    logs: trace.logs.map((log) => ({ ordinal: log.ordinal, logIndex: log.logIndex, address: log.address,
      topics: log.topics, dataSha256: log.data.sha256, dataByteLength: log.data.byteLength })),
    contentSha256: trace.contentSha256 };
}
function executionEvidence(database: DatabaseClient, scanId: string, executionId: string,
  selected: ReturnType<typeof subject>, artifacts: EvidenceArtifact[], warnings: EvidencePackage["warnings"]) {
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution || !["completed", "failed", "cancelled"].includes(execution.status))
    throw Error("evidence_execution_not_final");
  const poc = readImpactPoCArtifact(database, execution.artifactId);
  const fork = readImpactForkSession(database, execution.sessionId);
  if (!poc || !fork || poc.reviewState !== "reviewed" || poc.sourceSha256 !== execution.sourceSha256 ||
    impactPoCSourceHash(poc.source) !== poc.sourceSha256 ||
    fork.findingId !== poc.findingId || fork.hypothesisId !== poc.hypothesisId ||
    execution.chainId !== fork.chainId || execution.forkBlock !== fork.resolvedForkBlock ||
    execution.forkBlockHash !== fork.forkBlockHash ||
    JSON.stringify(execution.targetCodeHashes) !== JSON.stringify(fork.targetCodeHashes))
    throw Error("evidence_execution_binding_invalid");
  if (!(poc.findingId && selected.findingIds.includes(poc.findingId)) &&
    !(selected.value.type === "hypothesis" && poc.hypothesisId === selected.value.id))
    throw Error("evidence_wrong_subject");
  add(artifacts, "reviewed-poc", poc.id, "impact-reviewed-poc-v1", "available", poc.sourceSha256,
    [selected.value.id], 1, { id: poc.id, subject: { findingId: poc.findingId, hypothesisId: poc.hypothesisId },
      sourceSha256: poc.sourceSha256, source: safeSource(poc.source) ? poc.source : null,
      sourceOmitted: !safeSource(poc.source), entryContract: poc.entryContract, reviewedAt: poc.reviewedAt,
      forgeVersion: execution.forgeVersion, forgeSha256: execution.forgeSha256 });
  if (!safeSource(poc.source)) warnings.push({ artifactId: poc.id, message: "Reviewed PoC source omitted because sensitive text was detected." });
  add(artifacts, "fork-identity", fork.id, "impact-fork-identity-v1", "available", null, [poc.id], 1,
    { chainId: execution.chainId, forkBlock: execution.forkBlock, forkBlockHash: execution.forkBlockHash,
      targetContracts: fork.targetContracts, targetCodeHashes: execution.targetCodeHashes,
      anvilVersion: fork.anvilVersion, anvilSha256: fork.anvilSha256 });
  add(artifacts, "execution", execution.id, "impact-poc-execution-v1", "available", null,
    [poc.id, fork.id], execution.transactionHashes.length,
    { id: execution.id, status: execution.status, createdAt: execution.createdAt,
      startedAt: execution.startedAt, completedAt: execution.completedAt, executed: execution.executed,
      errorCode: execution.errorCode, transactionScope: execution.transactionScope,
      transactionHashes: execution.transactionHashes, observationPlanSha256: execution.observationPlanSha256,
      traceCaptureStatus: execution.traceCaptureStatus, traceIds: execution.traceIds,
      preSnapshotId: execution.preSnapshotId, postSnapshotId: execution.postSnapshotId,
      stateDiffId: execution.stateDiffId, finalReset: "unavailable" });
  const state = readImpactExecutionState(database, execution.id);
  add(artifacts, "state", `${execution.id}:state`, "impact-state-evidence-v1",
    state?.pre && state.post && state.diff ? "available" : state?.pre ? "partial" : "unavailable",
    state?.diff?.contentSha256 ?? state?.pre?.contentSha256 ?? null, [execution.id],
    (state?.pre?.observations.length ?? 0) + (state?.post?.observations.length ?? 0),
    { observationPlan: execution.observationPlan, pre: state?.pre ?? null,
      post: state?.post ?? null, diff: state?.diff ?? null });
  if (!state?.diff) warnings.push({ artifactId: `${execution.id}:state`, message: "POST state or diff unavailable; missing observations are not zero." });
  const traces = readImpactExecutionTraces(database, execution.id);
  add(artifacts, "trace", `${execution.id}:trace`, "impact-transaction-trace-v1",
    traces?.status === "finalized" && traces.traces.length === execution.transactionHashes.length ? "available" :
      traces?.traces.length ? "partial" : "unavailable", null, [execution.id], traces?.traces.length ?? 0,
    { status: traces?.status ?? null, traces: traces?.traces.map(traceProjection) ?? [] });
  if (traces?.status !== "finalized") warnings.push({ artifactId: `${execution.id}:trace`, message: "Trace evidence unavailable or partial." });
  let overlay = null, flow = null;
  try { overlay = loadImpactOverlay(database, scanId, execution.id); } catch { /* explicit capability below */ }
  add(artifacts, "impact-overlay", `${execution.id}:overlay`, "contracthunter-impact-overlay-v1",
    overlay ? "available" : "unavailable", overlay?.contentSha256 ?? null, [execution.id],
    overlay?.observedCalls.length ?? 0, overlay ? { contentSha256: overlay.contentSha256,
      derivationVersion: overlay.derivationVersion, coverage: overlay.coverage,
      transactions: overlay.transactions,
      calls: overlay.observedCalls.map((call) => ({ id: call.id, traceId: call.traceId,
        transactionHash: call.transactionHash, transactionOrdinal: call.transactionOrdinal,
        ordinal: call.ordinal, parentCallId: call.parentCallId, depth: call.depth,
        callType: call.callType, from: call.from, to: call.to, valueWei: call.valueWei,
        outcome: call.outcome, selector: call.selector, mapping: call.mapping,
        staticEdgeId: call.staticEdgeId, relationshipStatus: call.relationshipStatus })),
      logs: overlay.observedLogs.map((log) => ({ id: log.id, traceId: log.traceId,
        transactionHash: log.transactionHash, logIndex: log.logIndex, address: log.address,
        topics: log.topics, dataSha256: log.data.sha256,
        dataByteLength: log.data.byteLength, contractNodeId: log.contractNodeId })),
      pathComparisons: overlay.pathComparisons, warnings: overlay.warnings } : { reason: "overlay_unavailable" });
  try { flow = loadAssetFlow(database, scanId, execution.id); } catch { /* explicit capability below */ }
  add(artifacts, "asset-flow", `${execution.id}:assets`, "contracthunter-asset-flow-v1",
    flow ? flow.status === "complete-within-evidence" ? "available" : flow.status === "partial" ? "partial" : "unavailable" : "unavailable",
    flow?.contentSha256 ?? null, [execution.id], flow?.ledgerEntries.length ?? 0,
    flow ?? { reason: "asset_accounting_unavailable" });
  if (!flow || flow.status !== "complete-within-evidence") warnings.push({ artifactId: `${execution.id}:assets`,
    message: flow ? `Asset accounting is ${flow.status}.` : "Asset accounting is unavailable." });
  for (const message of [...(overlay?.warnings ?? []), ...(flow?.warnings ?? [])])
    warnings.push({ artifactId: flow?.executionId ?? execution.id, message: safeText(message) });
  return { execution, poc, fork, flow };
}

/** Read-only composition. Every selected ID is joined through persisted same-scan relationships. */
export function composeEvidencePackage(database: DatabaseClient, scanId: string,
  selection: EvidencePackageSelection, identity: { id: string; createdAt: number; status: "draft" | "finalized";
    finalizedAt: number | null }): EvidencePackage {
  if (!getScan(database, scanId) || !uuid.test(selection.subjectId) ||
    [selection.executionId, selection.scenarioRevisionId, selection.replayRunId].some((id) => id !== null && !uuid.test(id)) ||
    selection.scenarioRevisionId && !selection.executionId || selection.replayRunId && !selection.scenarioRevisionId)
    throw Error("evidence_selection_invalid");
  const selected = subject(database, scanId, selection.subjectType, selection.subjectId);
  const artifacts: EvidenceArtifact[] = [], warnings: EvidencePackage["warnings"] = [];
  const findingContext = selected.findingIds.slice(0, 32).flatMap((findingId) => {
    const row = getFinding(database, findingId);
    return row?.scanId === scanId ? [{ id: row.id, title: safeText(row.title), status: row.status,
      existingSeverity: row.severity, existingConfidence: row.confidence,
      scanner: row.source, detectorId: row.detectorId,
      sourceUnit: row.filePath && repositorySolidityPathSchema.safeParse(row.filePath).success ? row.filePath : null,
      startLine: row.startLine, endLine: row.endLine, contract: row.contract,
      functionName: row.functionName }] : [];
  });
  add(artifacts, "static-context", selected.value.id, "contracthunter-subject-context-v1", "available", null,
    [], selected.findingIds.length, { ...selected.value, findings: findingContext,
      findingLinksTruncated: selected.findingIds.length > 32 });
  if (selected.findingIds.length > 32) warnings.push({ artifactId: selected.value.id,
    message: "Static finding context is truncated to 32 exact linked findings." });
  const graph = readStaticProtocolGraph(database, scanId);
  const path = graph ? loadInvestigationPaths(database, scanId, selection.subjectType, selection.subjectId, graph) : null;
  if (graph && path) {
    const nodeIds = new Set(path.paths.flatMap((item) => item.nodeIds).concat(path.targetNodeIds));
    const edgeIds = new Set(path.paths.flatMap((item) => item.edgeIds));
    const nodes = graph.graph.nodes.filter((item) => nodeIds.has(item.id)).slice(0, 128);
    const edges = graph.graph.edges.filter((item) => edgeIds.has(item.id)).slice(0, 256);
    const graphTruncated = nodes.length !== nodeIds.size || edges.length !== edgeIds.size;
    add(artifacts, "protocol-graph-subset", graph.graph.id, graph.schema,
      graphTruncated ? "partial" : "available", graph.contentSha256,
      [selected.value.id], nodes.length + edges.length,
      { graphContentSha256: graph.contentSha256, nodes, edges,
        truncated: graphTruncated });
    if (graphTruncated) warnings.push({ artifactId: graph.graph.id,
      message: "Relevant ProtocolGraph context was truncated to the evidence-package bound." });
    add(artifacts, "investigation-path", `${selected.value.id}:path`, path.schema,
      path.coverage === "complete-within-bounds" ? "available" : "partial", path.contentSha256,
      [selected.value.id, graph.graph.id], path.paths.length, path);
    for (const message of path.warnings) warnings.push({ artifactId: `${selected.value.id}:path`, message });
    const relevant = deriveAllSecurityViews(graph).flatMap((view) => {
      const exactNodes = view.nodes.filter((item) => nodeIds.has(item.id)).map((item) => item.id);
      const exactEdges = view.edges.filter((item) => edgeIds.has(item.id)).map((item) => item.id);
      const annotations = view.annotations.filter((item) => nodeIds.has(item.nodeId)).map((item) => item.id);
      return exactNodes.length || exactEdges.length || annotations.length ? [{ viewType: view.viewType,
        id: view.id, contentSha256: view.contentSha256, nodeIds: exactNodes,
        edgeIds: exactEdges, annotationIds: annotations, warnings: view.warnings }] : [];
    });
    if (relevant.length) add(artifacts, "security-views", `${selected.value.id}:security-views`,
      "contracthunter-security-view-v1", "available", null, [graph.graph.id], relevant.length, relevant);
  }
  let sourceKey = selected.sourceKey, line = selected.line;
  if ((!sourceKey || !repositorySolidityPathSchema.safeParse(sourceKey).success) && path) {
    const source = path.paths.flatMap((item) => item.steps).find((item) => item.source);
    sourceKey = source?.source?.sourceUnitName ?? null; line = source?.source?.startLine ?? null;
  }
  if (sourceKey && repositorySolidityPathSchema.safeParse(sourceKey).success) {
    const source = getScanSource(database, scanId, sourceKey);
    if (source.available) {
      try {
        const excerpt = sourceExcerpt(source.rawBytes, line);
        if (safeSource(excerpt.excerpt)) add(artifacts, "source", `${scanId}:${sourceKey}`, "contracthunter-scan-source-snapshot-v1",
          "available", source.rawSha256, [selected.value.id], excerpt.endLine - excerpt.startLine + 1,
          { sourceUnit: sourceKey, rawSha256: source.rawSha256, byteLength: source.byteLength, ...excerpt });
        else warnings.push({ artifactId: selected.value.id, message: "Source excerpt omitted because sensitive text was detected." });
      } catch { warnings.push({ artifactId: selected.value.id, message: "Source excerpt unavailable from exact snapshot bytes." }); }
    }
  }
  if (selection.executionId) {
    const bound = executionEvidence(database, scanId, selection.executionId, selected, artifacts, warnings);
    if (selection.scenarioRevisionId) {
      const scenario = readImpactScenarioRevision(database, selection.scenarioRevisionId);
      if (!scenario || scenario.status !== "reviewed" || scenario.scanId !== scanId ||
        scenario.executionId !== bound.execution.id || scenario.subject.type !== (bound.poc.findingId ? "finding" : "hypothesis") ||
        scenario.subject.id !== (bound.poc.findingId ?? bound.poc.hypothesisId) ||
        !bound.flow || scenario.assetFlowContentSha256 !== bound.flow.contentSha256 ||
        scenario.assetAccountingRulesetVersion !== bound.flow.rulesetVersion)
        throw Error("evidence_scenario_stale_or_mismatched");
      const impact = deriveScenarioImpact(bound.flow, scenario);
      add(artifacts, "reviewed-scenario", scenario.id, scenario.schema, "available", scenario.contentSha256,
        [`${bound.execution.id}:assets`], scenario.assignments.length,
        { id: scenario.id, scenarioId: scenario.scenarioId, revision: scenario.revision,
          status: scenario.status, reviewedAt: scenario.reviewedAt, assignments: scenario.assignments,
          assetFlowContentSha256: scenario.assetFlowContentSha256, contentSha256: scenario.contentSha256,
          manualAnnotation: true });
      add(artifacts, "scenario-accounting", `${scenario.id}:impact`, impact.schema,
        impact.status === "complete-within-evidence" ? "available" : "partial", impact.contentSha256,
        [scenario.id], impact.rolePositions.length, impact);
      for (const message of impact.warnings) warnings.push({ artifactId: `${scenario.id}:impact`, message: safeText(message) });
      if (selection.replayRunId) {
        const run = readScenarioReplayRun(database, selection.replayRunId);
        const plan = run && readScenarioReplayPlan(database, run.planRevisionId);
        if (!run || !plan || plan.status !== "reviewed" || !["completed", "failed", "cancelled"].includes(run.status) ||
          plan.scanId !== scanId || plan.executionId !== bound.execution.id ||
          plan.scenarioRevisionId !== scenario.id || plan.artifactId !== bound.poc.id ||
          plan.sourceSha256 !== bound.poc.sourceSha256 || plan.assetFlowContentSha256 !== bound.flow.contentSha256 ||
          plan.scenarioContentSha256 !== scenario.contentSha256 || plan.chainId !== bound.execution.chainId ||
          plan.forkBlock !== bound.execution.forkBlock || plan.forkBlockHash !== bound.execution.forkBlockHash)
          throw Error("evidence_replay_binding_invalid");
        const result = readReplayResult(database, scanId, bound.execution.id, scenario.scenarioId,
          plan.planId, run.id).result;
        if (!result) throw Error("evidence_replay_result_unavailable");
        const finalReset = run.stopReason === "replay_final_reset_failed" ? "failed-fork-stopped" :
          run.stopReason === "replay_total_timeout" ? "unavailable" : "successful";
        add(artifacts, "replay", run.id, result.schema,
          result.repeatability === "partial" || result.repeatability === "unavailable" ? "partial" : "available",
          result.contentSha256, [scenario.id, bound.execution.id], result.iterations.length,
          { plan: { id: plan.id, planId: plan.planId, revision: plan.revision,
              contentSha256: plan.contentSha256, mode: plan.mode, iterationCount: plan.iterationCount,
              reviewedAt: plan.reviewedAt, rulesetVersion: result.rulesetVersion },
            run: { id: run.id, status: run.status, stopReason: run.stopReason,
              createdAt: run.createdAt, completedAt: run.completedAt, finalReset }, result });
        for (const item of result.iterations) {
          const iteration = item.iteration;
          const iterationExecution = iteration.executionId ? readImpactPoCExecution(database, iteration.executionId) : null;
          if (iterationExecution && (iterationExecution.artifactId !== bound.poc.id ||
            iterationExecution.sessionId !== bound.execution.sessionId ||
            iterationExecution.sourceSha256 !== bound.poc.sourceSha256))
            throw Error("evidence_replay_iteration_binding_invalid");
          const iterationState = iterationExecution ? readImpactExecutionState(database, iterationExecution.id) : null;
          const iterationTraces = iterationExecution ? readImpactExecutionTraces(database, iterationExecution.id) : null;
          const iterationFlow = iterationExecution && iteration.assetFlowContentSha256 ?
            loadAssetFlow(database, scanId, iterationExecution.id) : null;
          if (iteration.assetFlowContentSha256 && iterationFlow?.contentSha256 !== iteration.assetFlowContentSha256)
            throw Error("evidence_replay_iteration_asset_stale");
          add(artifacts, "replay-iteration", iteration.id, "contracthunter-scenario-replay-iteration-v1",
            iterationFlow && iterationState?.diff && iterationTraces?.status === "finalized" ? "available" : "partial",
            iterationFlow?.contentSha256 ?? null, [run.id], iterationFlow?.ledgerEntries.length ?? 0,
            { iteration, execution: iterationExecution ? {
                id: iterationExecution.id, status: iterationExecution.status,
                transactionHashes: iterationExecution.transactionHashes, errorCode: iterationExecution.errorCode } : null,
              state: iterationState ? { pre: iterationState.pre, post: iterationState.post,
                diff: iterationState.diff } : null,
              traces: iterationTraces?.traces.map(traceProjection) ?? [], assetFlow: iterationFlow,
              scenarioAccounting: item.accounting, matchedReference: item.matchedReference,
              variation: item.variation });
          if (!iterationFlow || !iterationState?.diff || iterationTraces?.status !== "finalized")
            warnings.push({ artifactId: iteration.id, message: "Replay iteration evidence is partial or unavailable." });
        }
        if (run.status !== "completed") warnings.push({ artifactId: run.id,
          message: `Replay ${run.status}; requested ${plan.iterationCount}, completed ${result.completedIterations}.` });
      }
    }
  }
  const allWarnings = [...new Map(warnings.map((item) => [`${item.artifactId}:${item.message}`, item])).values()]
    .sort((a, b) => `${a.artifactId}:${a.message}`.localeCompare(`${b.artifactId}:${b.message}`));
  const dedupedWarnings = allWarnings.length <= EVIDENCE_PACKAGE_LIMITS.warnings ? allWarnings :
    [...allWarnings.slice(0, EVIDENCE_PACKAGE_LIMITS.warnings - 1),
      { artifactId: selected.value.id,
        message: `Warning list truncated: ${allWarnings.length - EVIDENCE_PACKAGE_LIMITS.warnings + 1} additional warnings are not included.` }];
  const value = buildEvidencePackage({ packageId: identity.id, huntId: scanId, scanId, subject: selected.value,
    selection: { executionId: selection.executionId, scenarioRevisionId: selection.scenarioRevisionId,
      replayRunId: selection.replayRunId }, status: identity.status, artifacts,
    warnings: dedupedWarnings, createdAt: identity.createdAt, finalizedAt: identity.finalizedAt });
  if (!safeSource(canonicalEvidenceJson(value))) throw Error("evidence_sensitive_content_detected");
  return value;
}
export function createEvidencePackage(database: DatabaseClient, scanId: string, selection: EvidencePackageSelection) {
  return database.sqlite.transaction(() => {
    const draft = composeEvidencePackage(database, scanId, selection,
      { id: randomUUID(), createdAt: Date.now(), status: "draft", finalizedAt: null });
    return insertEvidencePackage(database, draft);
  }).immediate();
}
export function finalizeEvidencePackageFromCurrent(database: DatabaseClient, scanId: string, id: string) {
  return database.sqlite.transaction(() => {
    const draft = readEvidencePackage(database, scanId, id);
    if (!draft || draft.status !== "draft") throw Error("evidence_package_not_draft");
    const selection: EvidencePackageSelection = { subjectType: draft.subject.type, subjectId: draft.subject.id,
      ...draft.selection };
    const finalized = composeEvidencePackage(database, scanId, selection,
      { id, createdAt: draft.createdAt, status: "finalized", finalizedAt: Date.now() });
    return finalizeEvidencePackage(database, draft, finalized);
  }).immediate();
}
