import { buildBountyReport, canonicalEvidenceJson, verifyBountyReportIntegrity, type BountyReport } from "@contracthunter/core";
import { readEvidencePackage } from "./evidence-package";
import type { DatabaseClient } from "./index";

const REPORT_METADATA_SCHEMA = "contracthunter-bounty-report-metadata-v1";
type StoredReport = Pick<BountyReport, "reportId" | "revisionOf" | "status" | "evidencePackageId" |
  "evidencePackageContentHash" | "evidenceManifestHash" | "fields" | "createdAt" | "finalizedAt" | "contentHash"> &
  { schema: string };
function metadata(value: BountyReport): StoredReport {
  return { schema: REPORT_METADATA_SCHEMA, reportId: value.reportId, revisionOf: value.revisionOf,
    status: value.status, evidencePackageId: value.evidencePackageId,
    evidencePackageContentHash: value.evidencePackageContentHash, evidenceManifestHash: value.evidenceManifestHash,
    fields: value.fields, createdAt: value.createdAt, finalizedAt: value.finalizedAt,
    contentHash: value.contentHash };
}

export function readBountyReport(database: DatabaseClient, scanId: string, id: string): BountyReport | null {
  const row = database.sqlite.prepare("SELECT * FROM bounty_reports WHERE id=? AND scan_id=?")
    .get(id, scanId) as Record<string, unknown> | undefined;
  if (!row) return null;
  const pkg = readEvidencePackage(database, scanId, String(row.evidence_package_id));
  const stored = JSON.parse(String(row.report_json)) as StoredReport;
  if (!pkg || stored.reportId !== row.id || stored.status !== row.status ||
    stored.revisionOf !== row.revision_of || stored.evidencePackageId !== row.evidence_package_id ||
    stored.evidencePackageContentHash !== row.package_content_hash || stored.evidenceManifestHash !== row.manifest_hash ||
    stored.contentHash !== row.content_hash || stored.createdAt !== row.created_at || stored.finalizedAt !== row.finalized_at)
    throw Error("bounty_report_integrity_invalid");
  const value = buildBountyReport(pkg, stored.fields, { reportId: stored.reportId,
    revisionOf: stored.revisionOf, status: stored.status, createdAt: stored.createdAt,
    finalizedAt: stored.finalizedAt });
  if (verifyBountyReportIntegrity(value, pkg).status !== "valid" ||
    (stored.schema === REPORT_METADATA_SCHEMA ?
      canonicalEvidenceJson(stored) !== canonicalEvidenceJson(metadata(value)) :
      canonicalEvidenceJson(stored) !== canonicalEvidenceJson(value)))
    throw Error("bounty_report_integrity_invalid");
  return value;
}
export function insertBountyReport(database: DatabaseClient, scanId: string, value: BountyReport): BountyReport {
  const pkg = readEvidencePackage(database, scanId, value.evidencePackageId);
  if (!pkg || value.status !== "draft" || verifyBountyReportIntegrity(value, pkg).status !== "valid") throw Error("bounty_report_draft_invalid");
  if (value.revisionOf) {
    const prior = readBountyReport(database, scanId, value.revisionOf);
    if (!prior || prior.status !== "finalized" || prior.evidencePackageId !== value.evidencePackageId)
      throw Error("bounty_report_revision_invalid");
  }
  database.sqlite.prepare(`INSERT INTO bounty_reports
    (id,scan_id,evidence_package_id,revision_of,status,report_json,package_content_hash,manifest_hash,
     content_hash,created_at,finalized_at) VALUES (?,?,?,?,?,?,?,?,?,?,NULL)`).run(
    value.reportId, scanId, value.evidencePackageId, value.revisionOf, value.status,
    canonicalEvidenceJson(metadata(value)), value.evidencePackageContentHash, value.evidenceManifestHash,
    value.contentHash, value.createdAt);
  return value;
}
export function updateDraftBountyReport(database: DatabaseClient, scanId: string, value: BountyReport): BountyReport {
  const previous = readBountyReport(database, scanId, value.reportId);
  const pkg = readEvidencePackage(database, scanId, value.evidencePackageId);
  if (!previous || previous.status !== "draft" || !pkg || verifyBountyReportIntegrity(value, pkg).status !== "valid" ||
    value.status !== "draft" || value.revisionOf !== previous.revisionOf ||
    value.createdAt !== previous.createdAt || value.finalizedAt !== null ||
    value.evidencePackageId !== previous.evidencePackageId)
    throw Error("bounty_report_update_invalid");
  if (database.sqlite.prepare(`UPDATE bounty_reports SET report_json=?,content_hash=?
    WHERE id=? AND scan_id=? AND status='draft'`).run(canonicalEvidenceJson(metadata(value)), value.contentHash,
      value.reportId, scanId).changes !== 1) throw Error("bounty_report_not_draft");
  return value;
}
export function finalizeBountyReport(database: DatabaseClient, scanId: string, value: BountyReport): BountyReport {
  const previous = readBountyReport(database, scanId, value.reportId);
  const pkg = readEvidencePackage(database, scanId, value.evidencePackageId);
  if (!previous || previous.status !== "draft" || !pkg || verifyBountyReportIntegrity(value, pkg).status !== "valid" ||
    value.status !== "finalized" || value.revisionOf !== previous.revisionOf ||
    value.createdAt !== previous.createdAt || value.evidencePackageId !== previous.evidencePackageId ||
    canonicalEvidenceJson(value.fields) !== canonicalEvidenceJson(previous.fields) ||
    value.contentHash !== previous.contentHash || value.finalizedAt === null)
    throw Error("bounty_report_finalization_invalid");
  if (database.sqlite.prepare(`UPDATE bounty_reports SET status='finalized',report_json=?,finalized_at=?
    WHERE id=? AND scan_id=? AND status='draft'`).run(canonicalEvidenceJson(metadata(value)), value.finalizedAt,
      value.reportId, scanId).changes !== 1) throw Error("bounty_report_not_draft");
  return value;
}
export function listBountyReports(database: DatabaseClient, scanId: string, packageId: string):
  Array<{ id: string; status: string; createdAt: number; contentHash: string }> {
  return database.sqlite.prepare(`SELECT id,status,created_at AS createdAt,content_hash AS contentHash
    FROM bounty_reports WHERE scan_id=? AND evidence_package_id=? ORDER BY created_at DESC,id DESC LIMIT 32`)
    .all(scanId, packageId) as Array<{ id: string; status: string; createdAt: number; contentHash: string }>;
}

export function bountyReportRevision(database: DatabaseClient, scanId: string, report: BountyReport): number {
  let revision = 1, parentId = report.revisionOf;
  const seen = new Set([report.reportId]);
  while (parentId) {
    if (seen.has(parentId) || revision > 128) throw Error("bounty_report_revision_chain_invalid");
    seen.add(parentId);
    const parent = readBountyReport(database, scanId, parentId);
    if (!parent || parent.status !== "finalized" || parent.evidencePackageId !== report.evidencePackageId)
      throw Error("bounty_report_revision_chain_invalid");
    revision++; parentId = parent.revisionOf;
  }
  return revision;
}
