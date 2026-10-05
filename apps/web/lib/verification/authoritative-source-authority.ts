import { TextDecoder } from "node:util";
import { sourceEvidenceSchema, type ResolvedAuthoritativeSourceClosure } from "@contracthunter/core";
import { getScanCompilation, getScanSource, getVulnerabilityHypothesis, listInvestigationFindings,
  listScannerAlignments, type DatabaseClient, type VulnerabilityHypothesisRow } from "@contracthunter/db";
import { AuthoritativeClosureError, resolveAuthoritativeSourceClosure } from "@contracthunter/scanners";

export class AuthoritativeSourceError extends Error {
  constructor(readonly code: "authority_unavailable" | "unsupported_profile" | "unaligned_target" | "ambiguous_target" | "source_integrity_failed" | "invalid_utf8" | "unsupported_import" | "closure_limit") { super(code); this.name = "AuthoritativeSourceError"; }
}
export type SourceAuthority = { kind: "legacy"; reason: string } | { kind: "authoritative"; closure: ResolvedAuthoritativeSourceClosure; targetContract: string };

export function evidenceFor(hypothesis: VulnerabilityHypothesisRow): Array<{ filePath: string; contract: string | null; functionName: string | null; startLine: number | null; endLine: number | null }> {
  let raw: unknown;
  try { raw = JSON.parse(hypothesis.evidence); } catch { return []; }
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const result = sourceEvidenceSchema.safeParse({ filePath: record.filePath, contract: record.contract, functionName: record.functionName, startLine: record.startLine, endLine: record.endLine });
    return result.success ? [result.data] : [];
  });
}

/** The only adapter from persisted scan records to the pure authoritative closure resolver. */
export function sourceAuthorityForHypothesis(database: DatabaseClient, hypothesis: VulnerabilityHypothesisRow,
  requested?: { sourceUnitName: string; contract: string }): SourceAuthority {
  let provenance: ReturnType<typeof getScanCompilation>;
  try { provenance = getScanCompilation(database, hypothesis.scanId); }
  catch { throw new AuthoritativeSourceError("source_integrity_failed"); }
  if (provenance.status === "legacy_or_unavailable") return { kind: "legacy", reason: "legacy_or_unavailable" };
  if (provenance.status === "unsupported") return { kind: "legacy", reason: provenance.reason };
  const manifest = provenance.manifest;
  if (manifest.compilationProfileKind !== "plain-solidity-exact-pragma-v1") throw new AuthoritativeSourceError("unsupported_profile");
  const current = getVulnerabilityHypothesis(database, hypothesis.id);
  if (!current || current.scanId !== manifest.scanId) throw new AuthoritativeSourceError("authority_unavailable");
  let ids: unknown;
  try { ids = JSON.parse(hypothesis.relatedInvestigationIds); } catch { ids = null; }
  if (!Array.isArray(ids) || ids.some((id) => typeof id !== "string") || ids.length > 100) throw new AuthoritativeSourceError("unaligned_target");
  const linked = ids.flatMap((id) => listInvestigationFindings(database, id as string)).filter((finding) => finding.scanId === hypothesis.scanId);
  const aligned = new Map(listScannerAlignments(database, hypothesis.scanId).filter((item) => item.status === "aligned" && item.targetResolved).map((item) => [item.findingId, item]));
  const evidence = evidenceFor(hypothesis);
  const targets = new Set<string>();
  for (const finding of linked) {
    const alignment = aligned.get(finding.id);
    if (!alignment?.sourceUnitName || !finding.contract || !finding.filePath || alignment.sourceUnitName !== finding.filePath) continue;
    if (!evidence.some((item) => item.filePath === finding.filePath && item.contract === finding.contract)) continue;
    targets.add(`${finding.filePath}\0${finding.contract}`);
  }
  if (requested) {
    const key = `${requested.sourceUnitName}\0${requested.contract}`;
    if (!targets.has(key)) throw new AuthoritativeSourceError("unaligned_target");
    targets.clear(); targets.add(key);
  }
  if (!targets.size) throw new AuthoritativeSourceError("unaligned_target");
  if (targets.size !== 1) throw new AuthoritativeSourceError("ambiguous_target");
  const [targetSourceUnit, targetContract] = [...targets][0].split("\0");
  try {
    const closure = resolveAuthoritativeSourceClosure({ manifest, targetSourceUnit, source: (sourceKey) => {
      const source = getScanSource(database, hypothesis.scanId, sourceKey);
      return source.available ? source : null;
    } });
    return { kind: "authoritative", closure, targetContract };
  } catch (error) {
    if (error instanceof AuthoritativeClosureError) {
      const code = error.code === "invalid_utf8" ? "invalid_utf8" : error.code === "unsupported_import" ? "unsupported_import" : error.code === "closure_limit" ? "closure_limit" : error.code === "unsupported_profile" ? "unsupported_profile" : error.code === "target_unmappable" ? "unaligned_target" : "source_integrity_failed";
      throw new AuthoritativeSourceError(code);
    }
    throw new AuthoritativeSourceError("source_integrity_failed");
  }
}

export function textSources(closure: ResolvedAuthoritativeSourceClosure): Map<string, string> {
  const decoder = new TextDecoder("utf-8", { fatal: true }), sources = new Map<string, string>();
  try { for (const file of closure.files) sources.set(file.sourceUnitName, decoder.decode(file.rawBytes)); }
  catch { throw new AuthoritativeSourceError("invalid_utf8"); }
  return sources;
}

/** Explicit authoritative requests never enter the legacy compatibility path. */
export function requireAuthoritativeSourceClosureForHypothesis(database: DatabaseClient, hypothesis: VulnerabilityHypothesisRow,
  requested?: { sourceUnitName: string; contract: string }): Extract<SourceAuthority, { kind: "authoritative" }> {
  const authority = sourceAuthorityForHypothesis(database, hypothesis, requested);
  if (authority.kind === "legacy") throw new AuthoritativeSourceError(authority.reason === "legacy_or_unavailable" ? "authority_unavailable" : "unsupported_profile");
  return authority;
}
