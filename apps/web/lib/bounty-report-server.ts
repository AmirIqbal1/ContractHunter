import { randomUUID } from "node:crypto";
import { buildBountyReport, defaultBountyReportFields, type BountyReportFields } from "@contracthunter/core";
import { finalizeBountyReport, insertBountyReport, readBountyReport, readEvidencePackage,
  updateDraftBountyReport, type DatabaseClient } from "@contracthunter/db";

export function createReportDraft(database: DatabaseClient, scanId: string, packageId: string,
  revisionOf: string | null = null, fields?: BountyReportFields) {
  return database.sqlite.transaction(() => {
    const pkg = readEvidencePackage(database, scanId, packageId);
    if (!pkg || pkg.status !== "finalized") throw Error("bounty_report_package_not_finalized");
    const prior = revisionOf ? readBountyReport(database, scanId, revisionOf) : null;
    if (revisionOf && (!prior || prior.status !== "finalized" || prior.evidencePackageId !== pkg.packageId))
      throw Error("bounty_report_revision_invalid");
    if (revisionOf && fields) throw Error("bounty_report_revision_fields_invalid");
    const value = buildBountyReport(pkg, fields ?? prior?.fields ?? defaultBountyReportFields(pkg),
      { reportId: randomUUID(), revisionOf, status: "draft", createdAt: Date.now(), finalizedAt: null });
    return insertBountyReport(database, scanId, value);
  }).immediate();
}
export function saveReportDraft(database: DatabaseClient, scanId: string, reportId: string,
  fields: BountyReportFields) {
  return database.sqlite.transaction(() => {
    const previous = readBountyReport(database, scanId, reportId);
    if (!previous || previous.status !== "draft") throw Error("bounty_report_not_draft");
    const pkg = readEvidencePackage(database, scanId, previous.evidencePackageId);
    if (!pkg || pkg.status !== "finalized" || pkg.contentHash !== previous.evidencePackageContentHash ||
      pkg.manifestHash !== previous.evidenceManifestHash) throw Error("bounty_report_package_changed");
    return updateDraftBountyReport(database, scanId, buildBountyReport(pkg, fields,
      { reportId, revisionOf: previous.revisionOf, status: "draft",
        createdAt: previous.createdAt, finalizedAt: null }));
  }).immediate();
}
export function finalizeReportDraft(database: DatabaseClient, scanId: string, reportId: string) {
  return database.sqlite.transaction(() => {
    const previous = readBountyReport(database, scanId, reportId);
    if (!previous || previous.status !== "draft") throw Error("bounty_report_not_draft");
    const pkg = readEvidencePackage(database, scanId, previous.evidencePackageId);
    if (!pkg || pkg.status !== "finalized" || pkg.contentHash !== previous.evidencePackageContentHash ||
      pkg.manifestHash !== previous.evidenceManifestHash) throw Error("bounty_report_package_changed");
    return finalizeBountyReport(database, scanId, buildBountyReport(pkg, previous.fields,
      { reportId, revisionOf: previous.revisionOf, status: "finalized",
        createdAt: previous.createdAt, finalizedAt: Date.now() }));
  }).immediate();
}
