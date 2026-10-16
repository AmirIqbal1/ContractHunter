import { canonicalEvidenceJson, verifyEvidencePackageIntegrity, type EvidencePackage } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

export function readEvidencePackage(database: DatabaseClient, scanId: string, id: string): EvidencePackage | null {
  const row = database.sqlite.prepare("SELECT * FROM evidence_packages WHERE id=? AND scan_id=?")
    .get(id, scanId) as Record<string, unknown> | undefined;
  if (!row) return null;
  const value = JSON.parse(String(row.package_json)) as EvidencePackage;
  if (value.packageId !== row.id || value.scanId !== row.scan_id || value.huntId !== row.scan_id ||
    value.subject.type !== row.subject_type || value.subject.id !== row.subject_id ||
    value.status !== row.status || value.manifestHash !== row.manifest_sha256 ||
    value.contentHash !== row.content_sha256 || value.createdAt !== row.created_at ||
    value.finalizedAt !== row.finalized_at ||
    canonicalEvidenceJson(value.selection) !== String(row.selection_json) ||
    verifyEvidencePackageIntegrity(value).status !== "valid") throw Error("evidence_package_integrity_invalid");
  return value;
}
export function insertEvidencePackage(database: DatabaseClient, value: EvidencePackage): EvidencePackage {
  if (value.status !== "draft" || verifyEvidencePackageIntegrity(value).status !== "valid")
    throw Error("evidence_package_draft_invalid");
  database.sqlite.prepare(`INSERT INTO evidence_packages
    (id,scan_id,subject_type,subject_id,status,selection_json,package_json,manifest_sha256,
     content_sha256,created_at,finalized_at) VALUES (?,?,?,?,?,?,?,?,?,?,NULL)`).run(value.packageId,
    value.scanId, value.subject.type, value.subject.id, value.status, canonicalEvidenceJson(value.selection),
    canonicalEvidenceJson(value), value.manifestHash, value.contentHash, value.createdAt);
  return value;
}
export function finalizeEvidencePackage(database: DatabaseClient, draft: EvidencePackage,
  finalized: EvidencePackage): EvidencePackage {
  if (draft.status !== "draft" || finalized.status !== "finalized" || draft.packageId !== finalized.packageId ||
    draft.scanId !== finalized.scanId || draft.createdAt !== finalized.createdAt ||
    canonicalEvidenceJson(draft.selection) !== canonicalEvidenceJson(finalized.selection) ||
    draft.manifestHash !== finalized.manifestHash || draft.contentHash !== finalized.contentHash ||
    verifyEvidencePackageIntegrity(finalized).status !== "valid") throw Error("evidence_package_finalization_invalid");
  if (database.sqlite.prepare(`UPDATE evidence_packages SET status='finalized',package_json=?,
      manifest_sha256=?,content_sha256=?,finalized_at=? WHERE id=? AND scan_id=? AND status='draft'`)
    .run(canonicalEvidenceJson(finalized), finalized.manifestHash, finalized.contentHash,
      finalized.finalizedAt, finalized.packageId, finalized.scanId).changes !== 1)
    throw Error("evidence_package_not_draft");
  return finalized;
}
export function listEvidencePackages(database: DatabaseClient, scanId: string, subjectType: string,
  subjectId: string): Array<{ id: string; status: string; createdAt: number; contentHash: string }> {
  return (database.sqlite.prepare(`SELECT id,status,created_at AS createdAt,content_sha256 AS contentHash
    FROM evidence_packages WHERE scan_id=? AND subject_type=? AND subject_id=?
    ORDER BY created_at DESC,id DESC LIMIT 32`).all(scanId, subjectType, subjectId) as
    Array<{ id: string; status: string; createdAt: number; contentHash: string }>);
}
