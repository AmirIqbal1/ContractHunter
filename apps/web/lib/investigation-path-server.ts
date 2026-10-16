import { deriveInvestigationPaths, INVESTIGATION_PATH_LIMITS, investigationSubjectTypes,
  type InvestigationPathResult, type InvestigationPathSubject, type StaticProtocolGraphArtifact } from "@contracthunter/core";
import { getFinding, getInvestigation, getVulnerabilityHypothesis, listInvestigationFindings,
  readStaticProtocolGraph, type DatabaseClient } from "@contracthunter/db";

const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
export type PathSubjectType = (typeof investigationSubjectTypes)[number];
export function resolveInvestigationPathSubject(database: DatabaseClient, scanId: string,
  type: PathSubjectType, subjectId: string): InvestigationPathSubject | null {
  if (!uuid.test(subjectId)) return null;
  if (type === "finding") {
    const finding = getFinding(database, subjectId);
    return finding?.scanId === scanId ? { type, id: subjectId, findingIds: [subjectId] } : null;
  }
  if (type === "investigation") {
    const investigation = getInvestigation(database, subjectId);
    if (investigation?.scanId !== scanId) return null;
    const ids = [...new Set(listInvestigationFindings(database, subjectId).filter((item) => item.scanId === scanId)
      .map((item) => item.id))].sort();
    return { type, id: subjectId, findingIds: ids.slice(0, INVESTIGATION_PATH_LIMITS.findingRefs),
      linksTruncated: ids.length > INVESTIGATION_PATH_LIMITS.findingRefs };
  }
  const hypothesis = getVulnerabilityHypothesis(database, subjectId);
  if (hypothesis?.scanId !== scanId) return null;
  let related: unknown;
  try { related = JSON.parse(hypothesis.relatedInvestigationIds); } catch { related = []; }
  const investigationIds = Array.isArray(related) ? [...new Set(related.filter((id): id is string =>
    typeof id === "string" && uuid.test(id)))].sort() : [];
  const ids = [...new Set(investigationIds.slice(0, INVESTIGATION_PATH_LIMITS.findingRefs).flatMap((id) => {
    const investigation = getInvestigation(database, id);
    return investigation?.scanId === scanId ? listInvestigationFindings(database, id)
      .filter((finding) => finding.scanId === scanId).map((finding) => finding.id) : [];
  }))].sort();
  return { type, id: subjectId, findingIds: ids.slice(0, INVESTIGATION_PATH_LIMITS.findingRefs),
    linksTruncated: investigationIds.length > INVESTIGATION_PATH_LIMITS.findingRefs ||
      ids.length > INVESTIGATION_PATH_LIMITS.findingRefs };
}
export function loadInvestigationPaths(database: DatabaseClient, scanId: string, type: PathSubjectType,
  subjectId: string, suppliedArtifact?: StaticProtocolGraphArtifact): InvestigationPathResult | null {
  const subject = resolveInvestigationPathSubject(database, scanId, type, subjectId);
  if (!subject) return null;
  const artifact = suppliedArtifact ?? readStaticProtocolGraph(database, scanId);
  if (!artifact) return null;
  return deriveInvestigationPaths(artifact, subject);
}
