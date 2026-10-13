import { deriveImpactOverlay, type ImpactOverlay } from "@contracthunter/core";
import { getFinding, getScan, getVulnerabilityHypothesis, readImpactExecutionState,
  readImpactExecutionTraces, readImpactForkSession, readImpactPoCArtifact, readImpactPoCExecution,
  readStaticProtocolGraph, type DatabaseClient } from "@contracthunter/db";
import { loadInvestigationPaths } from "./investigation-path-server";

/** Exact execution → reviewed artifact → session → subject → scan membership. Read only. */
export function loadImpactOverlay(database: DatabaseClient, scanId: string, executionId: string): ImpactOverlay | null {
  if (!getScan(database, scanId)) return null;
  const execution = readImpactPoCExecution(database, executionId);
  if (!execution) return null;
  const artifact = readImpactPoCArtifact(database, execution.artifactId);
  const session = readImpactForkSession(database, execution.sessionId);
  if (!artifact || !session || artifact.reviewState !== "reviewed" ||
    artifact.findingId !== session.findingId || artifact.hypothesisId !== session.hypothesisId) return null;
  const subject = artifact.findingId ? getFinding(database, artifact.findingId) :
    artifact.hypothesisId ? getVulnerabilityHypothesis(database, artifact.hypothesisId) : null;
  if (!subject || subject.scanId !== scanId) return null;
  const state = readImpactExecutionState(database, executionId), traces = readImpactExecutionTraces(database, executionId);
  if (!state || !traces || traces.status !== execution.traceCaptureStatus) throw Error("impact_overlay_evidence_unavailable");
  const validTraces = traces.traces.map((trace) => {
    if (!trace) throw Error("impact_overlay_trace_unavailable");
    return trace;
  });
  const graph = readStaticProtocolGraph(database, scanId);
  const path = graph ? loadInvestigationPaths(database, scanId, artifact.findingId ? "finding" : "hypothesis",
    artifact.findingId ?? artifact.hypothesisId!, graph) : null;
  return deriveImpactOverlay({ scanId, execution, artifact, session, pre: state.pre, post: state.post,
    diff: state.diff, traces: validTraces, graph,
    investigationPath: path, trustedDeploymentBindings: [] });
}
