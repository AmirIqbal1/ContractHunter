import type { ImpactOverlay, ImpactPathComparison, InvestigationPathResult } from "@contracthunter/core";

/** Read-only display comparison for an Investigation containing the execution's exact finding. */
export function investigationImpactComparison(path: InvestigationPathResult, overlay: ImpactOverlay): ImpactPathComparison[] {
  if (path.subject.type !== "investigation" || overlay.subject.type !== "finding" ||
    !path.subject.findingIds.includes(overlay.subject.id) || path.scanId !== overlay.scanId ||
    path.protocolGraphId !== overlay.protocolGraphId || path.graphContentSha256 !== overlay.provenance.graphContentSha256)
    return [];
  const functions = new Set(overlay.observedCalls.flatMap((call) => call.mapping.functionNodeId ? [call.mapping.functionNodeId] : []));
  const contracts = new Set(overlay.observedCalls.flatMap((call) => call.mapping.contractNodeId ? [call.mapping.contractNodeId] : []));
  const edges = new Set(overlay.observedCalls.flatMap((call) => call.staticEdgeId ? [call.staticEdgeId] : []));
  const unresolved = !overlay.capabilities.traceAvailable || overlay.observedCalls.some((call) =>
    ["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"].includes(call.callType) && !call.mapping.functionNodeId);
  const runtimeOnlyCallIds = overlay.observedCalls.filter((call) => call.relationshipStatus === "runtime-only-observed").map((call) => call.id);
  return path.paths.map((item) => ({ pathId: item.id, subjectType: "investigation", subjectId: path.subject.id,
    steps: item.steps.map((step) => ({ nodeId: step.nodeId,
      status: functions.has(step.nodeId) || contracts.has(step.nodeId) ? "observed-in-this-local-execution" as const :
        !["function", "contract", "interface", "library"].includes(step.nodeKind) ? "static-context-only" as const :
          unresolved ? "comparison-unresolved" as const : "not-observed-in-this-execution" as const })),
    edges: item.edgeIds.map((edgeId, index) => ({ edgeId,
      status: !["calls", "external-call", "delegates"].includes(item.steps[index + 1]?.relationship ?? "") ?
        "static-context-only" as const : edges.has(edgeId) ? "observed-in-this-local-execution" as const :
          unresolved ? "comparison-unresolved" as const : "not-observed-in-this-execution" as const })),
    runtimeOnlyCallIds }));
}
