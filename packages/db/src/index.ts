import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { and, desc, eq, gte, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import type { AIAnalysisStatus, CompilerStatus, CompleteHypothesisVerificationRunInput, CreateHypothesisVerificationRunInput, CreateScanInput, DependencyStatus, DynamicEvidence, FailHypothesisVerificationRunInput, FindingStatus, HypothesisStatus, InvariantCategory, InvariantStatus, InvariantTestability, InvestigationStatus, NewFinding, ProtocolAnalysisResult, ReviewRunStatus, ReviewStageStatus, ScannerStatus, ScanStatus, SecurityReviewPlan, Severity, ValidatedEvidence } from "@contracthunter/core";
import { assertTransition, assertVerificationRunTransition, buildInvestigations, completeHypothesisVerificationRunSchema, correlateHypotheses, createHypothesisVerificationRunSchema, dynamicEvidenceSchema, failHypothesisVerificationRunSchema, findingSchema, investigationSchema, loadConfig, scanSchema } from "@contracthunter/core";
import { findings, hypothesisGroupMembers, hypothesisGroups, hypothesisVerificationRuns, investigationFindings, investigations, invariants, protocolAnalyses, scans, scanScanners, securityReviewerRuns, securityReviewPlans, vulnerabilityHypotheses, type FindingRow, type HypothesisGroupRow, type HypothesisVerificationRunRow, type InvariantRow, type InvestigationRow, type ProtocolAnalysisRow, type ScanRow, type ScanScannerRow, type SecurityReviewerRunRow, type SecurityReviewPlanRow, type VulnerabilityHypothesisRow } from "./schema";

export * from "./schema";

export type DatabaseClient = ReturnType<typeof createDatabase>;

export function createDatabase(databasePath: string) {
  mkdirSync(path.dirname(databasePath), { recursive: true });
  const sqlite = new Database(databasePath);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY, repository_url TEXT NOT NULL, repository_name TEXT NOT NULL,
      requested_ref TEXT, resolved_commit TEXT, status TEXT NOT NULL, framework TEXT NOT NULL,
      depth TEXT NOT NULL, created_at INTEGER NOT NULL, started_at INTEGER, completed_at INTEGER, error TEXT,
      scanner_name TEXT, scanner_status TEXT NOT NULL DEFAULT 'pending', scanner_duration_ms INTEGER,
      compiler_constraints TEXT, compiler_versions TEXT, compiler_detection_source TEXT,
      compiler_status TEXT NOT NULL DEFAULT 'pending', compiler_error TEXT,
      dependency_status TEXT NOT NULL DEFAULT 'pending', dependency_metadata TEXT, dependency_error TEXT,
      ai_status TEXT NOT NULL DEFAULT 'disabled', ai_error TEXT,
      review_status TEXT NOT NULL DEFAULT 'disabled', review_error TEXT
    );
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      title TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER NOT NULL, source TEXT NOT NULL,
      detector_id TEXT, fingerprint TEXT,
      contract TEXT, function_name TEXT, file_path TEXT, start_line INTEGER, end_line INTEGER,
      root_cause TEXT NOT NULL, attack_scenario TEXT NOT NULL, impact TEXT NOT NULL, evidence TEXT NOT NULL,
      status TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scan_scanners (
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      scanner_id TEXT NOT NULL, scanner_name TEXT NOT NULL, status TEXT NOT NULL,
      finding_count INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER, error TEXT, version TEXT,
      PRIMARY KEY (scan_id, scanner_id)
    );
    CREATE TABLE IF NOT EXISTS investigations (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      fingerprint TEXT NOT NULL UNIQUE, title TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
      priority_score INTEGER NOT NULL, confidence_score INTEGER NOT NULL, status TEXT NOT NULL,
      primary_file_path TEXT, primary_contract TEXT, primary_function TEXT, start_line INTEGER, end_line INTEGER,
      source_count INTEGER NOT NULL, reasons TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS investigation_findings (
      investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      PRIMARY KEY (investigation_id, finding_id)
    );
    CREATE TABLE IF NOT EXISTS protocol_analyses (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      provider TEXT NOT NULL, requested_model TEXT NOT NULL, actual_model TEXT, prompt_version TEXT NOT NULL,
      protocol_name TEXT NOT NULL, protocol_types TEXT NOT NULL, summary TEXT NOT NULL, architecture_summary TEXT NOT NULL, confidence INTEGER NOT NULL,
      coverage_status TEXT NOT NULL, context_manifest TEXT NOT NULL, assets TEXT NOT NULL, roles TEXT NOT NULL, entry_points TEXT NOT NULL, critical_state TEXT NOT NULL, external_dependencies TEXT NOT NULL, flows TEXT NOT NULL, trust_assumptions TEXT NOT NULL, limitations TEXT NOT NULL,
      created_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL, input_tokens INTEGER, output_tokens INTEGER, total_tokens INTEGER, request_id TEXT, is_latest INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invariants (
      id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES protocol_analyses(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL, severity_if_violated TEXT NOT NULL, confidence INTEGER NOT NULL, rationale TEXT NOT NULL,
      related_contracts TEXT NOT NULL, related_functions TEXT NOT NULL, related_state TEXT NOT NULL, source_evidence TEXT NOT NULL, testability TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_review_plans (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, protocol_analysis_id TEXT NOT NULL REFERENCES protocol_analyses(id) ON DELETE CASCADE,
      status TEXT NOT NULL, selected_reviewers TEXT NOT NULL, skipped_reviewers TEXT NOT NULL, estimated_source_bytes INTEGER NOT NULL, estimated_request_count INTEGER NOT NULL, actual_request_count INTEGER NOT NULL DEFAULT 0,
      total_input_tokens INTEGER, total_output_tokens INTEGER, total_tokens INTEGER, duration_ms INTEGER, error TEXT, created_at INTEGER NOT NULL, completed_at INTEGER, is_latest INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_reviewer_runs (
      id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES security_review_plans(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, protocol_analysis_id TEXT NOT NULL REFERENCES protocol_analyses(id) ON DELETE CASCADE,
      reviewer_id TEXT NOT NULL, reviewer_name TEXT NOT NULL, selection_reason TEXT NOT NULL, status TEXT NOT NULL, prompt_version TEXT NOT NULL, provider TEXT NOT NULL, requested_model TEXT NOT NULL, actual_model TEXT, context_manifest TEXT NOT NULL,
      summary TEXT, areas_reviewed TEXT NOT NULL, limitations TEXT NOT NULL, hypothesis_count INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER, output_tokens INTEGER, total_tokens INTEGER, duration_ms INTEGER, request_id TEXT, error TEXT, created_at INTEGER NOT NULL, started_at INTEGER, completed_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS vulnerability_hypotheses (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, protocol_analysis_id TEXT NOT NULL REFERENCES protocol_analyses(id) ON DELETE CASCADE, reviewer_id TEXT NOT NULL, reviewer_run_id TEXT NOT NULL REFERENCES security_reviewer_runs(id) ON DELETE CASCADE,
      title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, severity_justification TEXT NOT NULL, confidence INTEGER NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL, root_cause TEXT NOT NULL, preconditions TEXT NOT NULL, attack_path TEXT NOT NULL, impact TEXT NOT NULL, affected_assets TEXT NOT NULL, affected_contracts TEXT NOT NULL, affected_functions TEXT NOT NULL, evidence TEXT NOT NULL, violated_invariant_ids TEXT NOT NULL, related_investigation_ids TEXT NOT NULL, false_positive_risks TEXT NOT NULL, verification_strategy TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS hypothesis_verification_runs (
      id TEXT PRIMARY KEY, hypothesis_id TEXT NOT NULL REFERENCES vulnerability_hypotheses(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      resolved_commit TEXT NOT NULL, status TEXT NOT NULL, outcome TEXT, verifier_id TEXT NOT NULL, tool_name TEXT NOT NULL, tool_version TEXT, verification_strategy TEXT NOT NULL,
      result_summary TEXT, test_count INTEGER NOT NULL DEFAULT 0, passed_test_count INTEGER NOT NULL DEFAULT 0, failed_test_count INTEGER NOT NULL DEFAULT 0,
      stdout_summary TEXT NOT NULL DEFAULT '', stderr_summary TEXT NOT NULL DEFAULT '', dynamic_evidence TEXT NOT NULL DEFAULT '[]', error TEXT,
      created_at INTEGER NOT NULL, started_at INTEGER, completed_at INTEGER, duration_ms INTEGER
    );
    CREATE TABLE IF NOT EXISTS hypothesis_groups (
      id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES security_review_plans(id) ON DELETE CASCADE, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, priority_score INTEGER NOT NULL, confidence_score INTEGER NOT NULL, evidence_classes TEXT NOT NULL, reasons TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS hypothesis_group_members (
      group_id TEXT NOT NULL REFERENCES hypothesis_groups(id) ON DELETE CASCADE, hypothesis_id TEXT NOT NULL REFERENCES vulnerability_hypotheses(id) ON DELETE CASCADE, PRIMARY KEY (group_id, hypothesis_id)
    );
  `);
  const scanColumns = new Set((sqlite.prepare("PRAGMA table_info(scans)").all() as Array<{ name: string }>).map((column) => column.name));
  if (!scanColumns.has("scanner_name")) sqlite.exec("ALTER TABLE scans ADD COLUMN scanner_name TEXT");
  if (!scanColumns.has("scanner_status")) sqlite.exec("ALTER TABLE scans ADD COLUMN scanner_status TEXT NOT NULL DEFAULT 'pending'");
  if (!scanColumns.has("scanner_duration_ms")) sqlite.exec("ALTER TABLE scans ADD COLUMN scanner_duration_ms INTEGER");
  if (!scanColumns.has("compiler_constraints")) sqlite.exec("ALTER TABLE scans ADD COLUMN compiler_constraints TEXT");
  if (!scanColumns.has("compiler_versions")) sqlite.exec("ALTER TABLE scans ADD COLUMN compiler_versions TEXT");
  if (!scanColumns.has("compiler_detection_source")) sqlite.exec("ALTER TABLE scans ADD COLUMN compiler_detection_source TEXT");
  if (!scanColumns.has("compiler_status")) sqlite.exec("ALTER TABLE scans ADD COLUMN compiler_status TEXT NOT NULL DEFAULT 'pending'");
  if (!scanColumns.has("compiler_error")) sqlite.exec("ALTER TABLE scans ADD COLUMN compiler_error TEXT");
  if (!scanColumns.has("dependency_status")) sqlite.exec("ALTER TABLE scans ADD COLUMN dependency_status TEXT NOT NULL DEFAULT 'pending'");
  if (!scanColumns.has("dependency_metadata")) sqlite.exec("ALTER TABLE scans ADD COLUMN dependency_metadata TEXT");
  if (!scanColumns.has("dependency_error")) sqlite.exec("ALTER TABLE scans ADD COLUMN dependency_error TEXT");
  if (!scanColumns.has("ai_status")) sqlite.exec("ALTER TABLE scans ADD COLUMN ai_status TEXT NOT NULL DEFAULT 'disabled'");
  if (!scanColumns.has("ai_error")) sqlite.exec("ALTER TABLE scans ADD COLUMN ai_error TEXT");
  if (!scanColumns.has("review_status")) sqlite.exec("ALTER TABLE scans ADD COLUMN review_status TEXT NOT NULL DEFAULT 'disabled'");
  if (!scanColumns.has("review_error")) sqlite.exec("ALTER TABLE scans ADD COLUMN review_error TEXT");
  const findingColumns = new Set((sqlite.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>).map((column) => column.name));
  if (!findingColumns.has("detector_id")) sqlite.exec("ALTER TABLE findings ADD COLUMN detector_id TEXT");
  if (!findingColumns.has("fingerprint")) sqlite.exec("ALTER TABLE findings ADD COLUMN fingerprint TEXT");
  sqlite.exec(`
    CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS findings_filters_idx ON findings(severity, status, source);
    CREATE UNIQUE INDEX IF NOT EXISTS findings_fingerprint_idx ON findings(fingerprint) WHERE fingerprint IS NOT NULL;
    CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at);
    CREATE INDEX IF NOT EXISTS scan_scanners_scan_id_idx ON scan_scanners(scan_id);
    CREATE INDEX IF NOT EXISTS investigations_scan_id_idx ON investigations(scan_id);
    CREATE INDEX IF NOT EXISTS investigations_queue_idx ON investigations(priority_score, confidence_score, status);
    CREATE INDEX IF NOT EXISTS investigation_findings_finding_id_idx ON investigation_findings(finding_id);
    CREATE INDEX IF NOT EXISTS protocol_analyses_scan_idx ON protocol_analyses(scan_id, is_latest);
    CREATE INDEX IF NOT EXISTS invariants_scan_idx ON invariants(scan_id, severity_if_violated, status);
    CREATE INDEX IF NOT EXISTS security_review_plans_scan_idx ON security_review_plans(scan_id, is_latest);
    CREATE INDEX IF NOT EXISTS security_reviewer_runs_plan_idx ON security_reviewer_runs(plan_id, status);
    CREATE INDEX IF NOT EXISTS vulnerability_hypotheses_scan_idx ON vulnerability_hypotheses(scan_id, severity, status, confidence);
    CREATE INDEX IF NOT EXISTS hypothesis_verification_runs_hypothesis_idx ON hypothesis_verification_runs(hypothesis_id, created_at);
    CREATE INDEX IF NOT EXISTS hypothesis_groups_plan_idx ON hypothesis_groups(plan_id, priority_score);
    CREATE INDEX IF NOT EXISTS hypothesis_group_members_hypothesis_idx ON hypothesis_group_members(hypothesis_id);
  `);
  const orm = drizzle(sqlite, { schema: { scans, findings, scanScanners, investigations, investigationFindings, protocolAnalyses, invariants, securityReviewPlans, securityReviewerRuns, vulnerabilityHypotheses, hypothesisVerificationRuns, hypothesisGroups, hypothesisGroupMembers } });
  return { sqlite, orm };
}

let singleton: DatabaseClient | undefined;
export function getDatabase(): DatabaseClient {
  if (!singleton) {
    singleton = createDatabase(loadConfig().DATABASE_PATH);
    backfillInvestigations(singleton);
  }
  return singleton;
}

export function closeDatabase(database: DatabaseClient): void {
  database.sqlite.close();
}

export function createScan(database: DatabaseClient, input: CreateScanInput & { repositoryUrl: string; repositoryName: string }): ScanRow {
  const row: ScanRow = {
    id: randomUUID(), repositoryUrl: input.repositoryUrl, repositoryName: input.repositoryName,
    requestedRef: input.requestedRef ?? null, resolvedCommit: null, status: "queued", framework: "unknown",
    depth: input.depth, createdAt: new Date(), startedAt: null, completedAt: null, error: null,
    scannerName: "Slither", scannerStatus: "pending", scannerDurationMs: null,
    compilerConstraints: null, compilerVersions: null, compilerDetectionSource: null, compilerStatus: "pending", compilerError: null,
    dependencyStatus: "pending", dependencyMetadata: null, dependencyError: null,
    aiStatus: "disabled", aiError: null,
    reviewStatus: "disabled", reviewError: null,
  };
  scanSchema.parse(row);
  database.orm.insert(scans).values(row).run();
  return row;
}

export function getScan(database: DatabaseClient, id: string): ScanRow | undefined {
  return database.orm.select().from(scans).where(eq(scans.id, id)).get();
}

export function listScans(database: DatabaseClient, limit = 100): ScanRow[] {
  return database.orm.select().from(scans).orderBy(desc(scans.createdAt)).limit(limit).all();
}

export function transitionScan(database: DatabaseClient, id: string, status: ScanStatus, fields: Partial<Pick<ScanRow, "resolvedCommit" | "framework" | "error">> = {}): ScanRow {
  const current = getScan(database, id);
  if (!current) throw new Error("Scan not found.");
  assertTransition(current.status, status);
  const timing = {
    ...(status === "cloning" && !current.startedAt ? { startedAt: new Date() } : {}),
    ...(["completed", "failed"].includes(status) ? { completedAt: new Date() } : {}),
  };
  database.orm.update(scans).set({ status, ...fields, ...timing }).where(eq(scans.id, id)).run();
  const updated = getScan(database, id);
  if (!updated) throw new Error("Scan disappeared during update.");
  return updated;
}

export function updateScanMetadata(database: DatabaseClient, id: string, fields: Partial<Pick<ScanRow, "resolvedCommit" | "framework">>): void {
  database.orm.update(scans).set(fields).where(eq(scans.id, id)).run();
}

export function updateScannerState(database: DatabaseClient, id: string, scannerName: string, scannerStatus: ScannerStatus, scannerDurationMs?: number): void {
  database.orm.update(scans).set({ scannerName, scannerStatus, ...(scannerDurationMs === undefined ? {} : { scannerDurationMs }) }).where(eq(scans.id, id)).run();
}

export type ScannerStateUpdate = {
  scannerId: string;
  scannerName: string;
  status: ScannerStatus;
  findingCount?: number;
  durationMs?: number | null;
  error?: string | null;
  version?: string | null;
};

export function upsertScanScanner(database: DatabaseClient, scanId: string, update: ScannerStateUpdate): void {
  database.orm.insert(scanScanners).values({
    scanId,
    scannerId: update.scannerId,
    scannerName: update.scannerName,
    status: update.status,
    findingCount: update.findingCount ?? 0,
    durationMs: update.durationMs ?? null,
    error: update.error ?? null,
    version: update.version ?? null,
  }).onConflictDoUpdate({
    target: [scanScanners.scanId, scanScanners.scannerId],
    set: {
      scannerName: update.scannerName,
      status: update.status,
      ...(update.findingCount === undefined ? {} : { findingCount: update.findingCount }),
      ...(update.durationMs === undefined ? {} : { durationMs: update.durationMs }),
      ...(update.error === undefined ? {} : { error: update.error }),
      ...(update.version === undefined ? {} : { version: update.version }),
    },
  }).run();
}

export function listScanScanners(database: DatabaseClient, scanId: string): ScanScannerRow[] {
  return database.orm.select().from(scanScanners).where(eq(scanScanners.scanId, scanId)).all();
}

export type CompilerMetadataUpdate = {
  status: CompilerStatus;
  constraints?: string[];
  versions?: string[];
  detectionSource?: "foundry-config" | "pragma";
  error?: string | null;
};

export function updateCompilerState(database: DatabaseClient, id: string, update: CompilerMetadataUpdate): void {
  database.orm.update(scans).set({
    compilerStatus: update.status,
    ...(update.constraints ? { compilerConstraints: JSON.stringify(update.constraints) } : {}),
    ...(update.versions ? { compilerVersions: JSON.stringify(update.versions) } : {}),
    ...(update.detectionSource ? { compilerDetectionSource: update.detectionSource } : {}),
    ...(update.error !== undefined ? { compilerError: update.error } : {}),
  }).where(eq(scans.id, id)).run();
}

export function updateDependencyState(database: DatabaseClient, id: string, status: DependencyStatus, metadata?: unknown, error?: string | null): void {
  database.orm.update(scans).set({
    dependencyStatus: status,
    ...(metadata === undefined ? {} : { dependencyMetadata: JSON.stringify(metadata) }),
    ...(error === undefined ? {} : { dependencyError: error }),
  }).where(eq(scans.id, id)).run();
}

export function updateAIState(database: DatabaseClient, id: string, status: AIAnalysisStatus, error: string | null = null): void {
  database.orm.update(scans).set({ aiStatus: status, aiError: error }).where(eq(scans.id, id)).run();
}

export function updateSecurityReviewState(database: DatabaseClient, id: string, status: ReviewStageStatus, error: string | null = null): void {
  database.orm.update(scans).set({ reviewStatus: status, reviewError: error }).where(eq(scans.id, id)).run();
}

export function markActiveScansInterrupted(database: DatabaseClient): number {
  const active: ScanStatus[] = ["queued", "cloning", "detecting", "preparing_dependencies", "preparing_compiler", "scanning"];
  const result = database.orm.update(scans).set({ status: "failed", scannerStatus: "failed", compilerStatus: "failed", dependencyStatus: "failed", completedAt: new Date(), error: "Scan interrupted by application restart." }).where(inArray(scans.status, active)).run().changes;
  database.sqlite.prepare("UPDATE scan_scanners SET status = 'failed', error = 'Scan interrupted by application restart.' WHERE status IN ('pending', 'available', 'running')").run();
  database.sqlite.prepare("UPDATE scans SET ai_status = 'failed', ai_error = 'AI analysis interrupted by application restart.' WHERE ai_status IN ('pending', 'running')").run();
  database.sqlite.prepare("UPDATE scans SET review_status = 'failed', review_error = 'Security review interrupted by application restart.' WHERE review_status IN ('pending', 'running')").run();
  database.sqlite.prepare("UPDATE security_review_plans SET status = 'failed', error = 'Security review interrupted by application restart.', completed_at = unixepoch() * 1000 WHERE status IN ('pending', 'running')").run();
  database.sqlite.prepare("UPDATE security_reviewer_runs SET status = 'failed', error = 'Reviewer interrupted by application restart.', completed_at = unixepoch() * 1000 WHERE status IN ('queued', 'running')").run();
  return result;
}

export function insertFindings(database: DatabaseClient, scanId: string, input: NewFinding[]): FindingRow[] {
  const rows = input.map((finding) => {
    const row = { ...finding, id: randomUUID(), scanId, createdAt: new Date() };
    findingSchema.parse(row);
    return row;
  });
  if (!rows.length) return [];
  database.orm.insert(findings).values(rows).onConflictDoNothing().run();
  return rows.filter((row) => getFindingByFingerprint(database, row.fingerprint)?.id === row.id);
}

function getFindingByFingerprint(database: DatabaseClient, fingerprint: string): FindingRow | undefined {
  return database.orm.select().from(findings).where(eq(findings.fingerprint, fingerprint)).get();
}

export type FindingFilters = { scanId?: string; severity?: Severity; source?: string; status?: FindingStatus };
export function listFindings(database: DatabaseClient, filters: FindingFilters = {}): FindingRow[] {
  const clauses = [
    filters.scanId ? eq(findings.scanId, filters.scanId) : undefined,
    filters.severity ? eq(findings.severity, filters.severity) : undefined,
    filters.source ? eq(findings.source, filters.source) : undefined,
    filters.status ? eq(findings.status, filters.status) : undefined,
  ].filter((clause): clause is NonNullable<typeof clause> => Boolean(clause));
  return database.orm.select().from(findings).where(clauses.length ? and(...clauses) : undefined).orderBy(desc(findings.createdAt)).all();
}

export function getFinding(database: DatabaseClient, id: string): FindingRow | undefined {
  return database.orm.select().from(findings).where(eq(findings.id, id)).get();
}

export type InvestigationFilters = { scanId?: string; severity?: Severity; status?: InvestigationStatus; minimumConfidence?: number; sourceCount?: number };

export function listInvestigations(database: DatabaseClient, filters: InvestigationFilters = {}, limit = 500): InvestigationRow[] {
  const clauses = [
    filters.scanId ? eq(investigations.scanId, filters.scanId) : undefined,
    filters.severity ? eq(investigations.severity, filters.severity) : undefined,
    filters.status ? eq(investigations.status, filters.status) : undefined,
    filters.minimumConfidence === undefined ? undefined : gte(investigations.confidenceScore, filters.minimumConfidence),
    filters.sourceCount === undefined ? undefined : gte(investigations.sourceCount, filters.sourceCount),
  ].filter((clause): clause is NonNullable<typeof clause> => Boolean(clause));
  return database.orm.select().from(investigations).where(clauses.length ? and(...clauses) : undefined).orderBy(desc(investigations.priorityScore), desc(investigations.confidenceScore), investigations.fingerprint).limit(limit).all();
}

export function getInvestigation(database: DatabaseClient, id: string): InvestigationRow | undefined {
  return database.orm.select().from(investigations).where(eq(investigations.id, id)).get();
}

export function listInvestigationFindings(database: DatabaseClient, investigationId: string): FindingRow[] {
  const relationRows = database.orm.select({ findingId: investigationFindings.findingId }).from(investigationFindings).where(eq(investigationFindings.investigationId, investigationId)).all();
  if (!relationRows.length) return [];
  return database.orm.select().from(findings).where(inArray(findings.id, relationRows.map((row) => row.findingId))).orderBy(findings.source, findings.fingerprint).all();
}

export function updateInvestigationStatus(database: DatabaseClient, id: string, status: InvestigationStatus): InvestigationRow | undefined {
  database.orm.update(investigations).set({ status, updatedAt: new Date() }).where(eq(investigations.id, id)).run();
  return getInvestigation(database, id);
}

export function reconcileInvestigations(database: DatabaseClient, scanId: string): InvestigationRow[] {
  const raw = listFindings(database, { scanId });
  const built = buildInvestigations(raw);
  const existing = database.orm.select().from(investigations).where(eq(investigations.scanId, scanId)).all();
  const existingByFingerprint = new Map(existing.map((item) => [item.fingerprint, item]));
  const now = new Date();
  database.sqlite.transaction(() => {
    database.sqlite.prepare("DELETE FROM investigation_findings WHERE investigation_id IN (SELECT id FROM investigations WHERE scan_id = ?)").run(scanId);
    const keep = new Set<string>();
    for (const candidate of built) {
      const previous = existingByFingerprint.get(candidate.fingerprint);
      const id = previous?.id ?? randomUUID();
      const row: InvestigationRow = {
        id, scanId, fingerprint: candidate.fingerprint, title: candidate.title, severity: candidate.severity, category: candidate.category,
        priorityScore: candidate.priorityScore, confidenceScore: candidate.confidenceScore, status: previous?.status ?? "candidate",
        primaryFilePath: candidate.primaryFilePath, primaryContract: candidate.primaryContract, primaryFunction: candidate.primaryFunction,
        startLine: candidate.startLine, endLine: candidate.endLine, sourceCount: candidate.sourceCount, reasons: JSON.stringify(candidate.reasons),
        createdAt: previous?.createdAt ?? now, updatedAt: now,
      };
      investigationSchema.parse(row);
      database.orm.insert(investigations).values(row).onConflictDoUpdate({ target: investigations.fingerprint, set: { title: row.title, severity: row.severity, category: row.category, priorityScore: row.priorityScore, confidenceScore: row.confidenceScore, primaryFilePath: row.primaryFilePath, primaryContract: row.primaryContract, primaryFunction: row.primaryFunction, startLine: row.startLine, endLine: row.endLine, sourceCount: row.sourceCount, reasons: row.reasons, updatedAt: now } }).run();
      database.orm.insert(investigationFindings).values(candidate.findingIds.map((findingId) => ({ investigationId: id, findingId }))).onConflictDoNothing().run();
      keep.add(candidate.fingerprint);
    }
    for (const obsolete of existing.filter((item) => !keep.has(item.fingerprint))) database.orm.delete(investigations).where(eq(investigations.id, obsolete.id)).run();
  })();
  return listInvestigations(database, { scanId });
}

export function backfillInvestigations(database: DatabaseClient): number {
  const candidates = database.sqlite.prepare("SELECT s.id FROM scans s WHERE s.status = 'completed' AND EXISTS (SELECT 1 FROM findings f WHERE f.scan_id = s.id) AND NOT EXISTS (SELECT 1 FROM investigations i WHERE i.scan_id = s.id)").all() as Array<{ id: string }>;
  for (const candidate of candidates) reconcileInvestigations(database, candidate.id);
  return candidates.length;
}

export type PersistProtocolAnalysisInput = {
  scanId: string; provider: string; requestedModel: string; actualModel: string | null; promptVersion: string;
  result: ProtocolAnalysisResult; coverageStatus: "complete" | "partial"; contextManifest: unknown;
  durationMs: number; inputTokens: number | null; outputTokens: number | null; totalTokens: number | null; requestId: string | null;
};

export function createProtocolAnalysis(database: DatabaseClient, input: PersistProtocolAnalysisInput): ProtocolAnalysisRow {
  const id = randomUUID(); const createdAt = new Date();
  const row: ProtocolAnalysisRow = {
    id, scanId: input.scanId, provider: input.provider, requestedModel: input.requestedModel, actualModel: input.actualModel, promptVersion: input.promptVersion,
    protocolName: input.result.protocol.name, protocolTypes: JSON.stringify(input.result.protocol.types), summary: input.result.protocol.summary, architectureSummary: input.result.protocol.architectureSummary, confidence: input.result.protocol.confidence,
    coverageStatus: input.coverageStatus, contextManifest: JSON.stringify(input.contextManifest), assets: JSON.stringify(input.result.assets), roles: JSON.stringify(input.result.roles), entryPoints: JSON.stringify(input.result.entryPoints), criticalState: JSON.stringify(input.result.criticalState), externalDependencies: JSON.stringify(input.result.externalDependencies), flows: JSON.stringify(input.result.flows), trustAssumptions: JSON.stringify(input.result.trustAssumptions), limitations: JSON.stringify(input.result.limitations),
    createdAt, durationMs: input.durationMs, inputTokens: input.inputTokens, outputTokens: input.outputTokens, totalTokens: input.totalTokens, requestId: input.requestId, isLatest: true,
  };
  database.sqlite.transaction(() => {
    database.orm.update(protocolAnalyses).set({ isLatest: false }).where(eq(protocolAnalyses.scanId, input.scanId)).run();
    database.orm.insert(protocolAnalyses).values(row).run();
    if (input.result.invariants.length) database.orm.insert(invariants).values(input.result.invariants.map((item) => ({
      id: randomUUID(), analysisId: id, scanId: input.scanId, title: item.title, description: item.description, category: item.category, severityIfViolated: item.severityIfViolated, confidence: item.confidence, rationale: item.rationale,
      relatedContracts: JSON.stringify(item.relatedContracts), relatedFunctions: JSON.stringify(item.relatedFunctions), relatedState: JSON.stringify(item.relatedState), sourceEvidence: JSON.stringify(item.sourceEvidence as ValidatedEvidence[]), testability: item.testability, status: "proposed" as const, createdAt,
    }))).run();
  })();
  return row;
}

export function getCurrentProtocolAnalysis(database: DatabaseClient, scanId: string): ProtocolAnalysisRow | undefined {
  return database.orm.select().from(protocolAnalyses).where(and(eq(protocolAnalyses.scanId, scanId), eq(protocolAnalyses.isLatest, true))).get();
}

export function getProtocolAnalysis(database: DatabaseClient, id: string): ProtocolAnalysisRow | undefined {
  return database.orm.select().from(protocolAnalyses).where(eq(protocolAnalyses.id, id)).get();
}

export function listProtocolAnalyses(database: DatabaseClient, scanId: string): ProtocolAnalysisRow[] {
  return database.orm.select().from(protocolAnalyses).where(eq(protocolAnalyses.scanId, scanId)).orderBy(desc(protocolAnalyses.createdAt)).all();
}

export type InvariantFilters = { scanId?: string; category?: InvariantCategory; severity?: Severity; status?: InvariantStatus; testability?: InvariantTestability };
export function listInvariants(database: DatabaseClient, filters: InvariantFilters = {}, latestOnly = true): InvariantRow[] {
  const clauses = [filters.scanId ? eq(invariants.scanId, filters.scanId) : undefined, filters.category ? eq(invariants.category, filters.category) : undefined, filters.severity ? eq(invariants.severityIfViolated, filters.severity) : undefined, filters.status ? eq(invariants.status, filters.status) : undefined, filters.testability ? eq(invariants.testability, filters.testability) : undefined, latestOnly ? eq(protocolAnalyses.isLatest, true) : undefined].filter((clause): clause is NonNullable<typeof clause> => Boolean(clause));
  return database.orm.select({ invariant: invariants }).from(invariants).innerJoin(protocolAnalyses, eq(invariants.analysisId, protocolAnalyses.id)).where(and(...clauses)).orderBy(sql`CASE ${invariants.severityIfViolated} WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC`, desc(invariants.confidence), invariants.title).all().map((row) => row.invariant);
}

export function getInvariant(database: DatabaseClient, id: string): InvariantRow | undefined { return database.orm.select().from(invariants).where(eq(invariants.id, id)).get(); }
export function updateInvariantStatus(database: DatabaseClient, id: string, status: InvariantStatus): InvariantRow | undefined {
  database.orm.update(invariants).set({ status }).where(eq(invariants.id, id)).run();
  return getInvariant(database, id);
}

export function createSecurityReviewPlan(database: DatabaseClient, input: { scanId: string; protocolAnalysisId: string; plan: SecurityReviewPlan; estimatedSourceBytes: number }): SecurityReviewPlanRow {
  const row: SecurityReviewPlanRow = { id: randomUUID(), scanId: input.scanId, protocolAnalysisId: input.protocolAnalysisId, status: "pending", selectedReviewers: JSON.stringify(input.plan.selected), skippedReviewers: JSON.stringify(input.plan.skipped), estimatedSourceBytes: input.estimatedSourceBytes, estimatedRequestCount: input.plan.estimatedRequestCount, actualRequestCount: 0, totalInputTokens: null, totalOutputTokens: null, totalTokens: null, durationMs: null, error: null, createdAt: new Date(), completedAt: null, isLatest: true };
  database.sqlite.transaction(() => { database.orm.update(securityReviewPlans).set({ isLatest: false }).where(eq(securityReviewPlans.scanId, input.scanId)).run(); database.orm.insert(securityReviewPlans).values(row).run(); updateSecurityReviewState(database, input.scanId, "pending"); })();
  return row;
}
export function getCurrentSecurityReviewPlan(database: DatabaseClient, scanId: string): SecurityReviewPlanRow | undefined { return database.orm.select().from(securityReviewPlans).where(and(eq(securityReviewPlans.scanId, scanId), eq(securityReviewPlans.isLatest, true))).get(); }
export function getSecurityReviewPlan(database: DatabaseClient, id: string): SecurityReviewPlanRow | undefined { return database.orm.select().from(securityReviewPlans).where(eq(securityReviewPlans.id, id)).get(); }
export function listSecurityReviewPlans(database: DatabaseClient, scanId: string): SecurityReviewPlanRow[] { return database.orm.select().from(securityReviewPlans).where(eq(securityReviewPlans.scanId, scanId)).orderBy(desc(securityReviewPlans.createdAt)).all(); }
export function updateSecurityReviewPlan(database: DatabaseClient, id: string, fields: Partial<Pick<SecurityReviewPlanRow, "status" | "actualRequestCount" | "totalInputTokens" | "totalOutputTokens" | "totalTokens" | "durationMs" | "error" | "completedAt">>): void { database.orm.update(securityReviewPlans).set(fields).where(eq(securityReviewPlans.id, id)).run(); }

export function createSecurityReviewerRun(database: DatabaseClient, input: { planId: string; scanId: string; protocolAnalysisId: string; reviewerId: string; reviewerName: string; selectionReason: string; promptVersion: string; provider: string; requestedModel: string; contextManifest: unknown }): SecurityReviewerRunRow {
  const row: SecurityReviewerRunRow = { id: randomUUID(), planId: input.planId, scanId: input.scanId, protocolAnalysisId: input.protocolAnalysisId, reviewerId: input.reviewerId, reviewerName: input.reviewerName, selectionReason: input.selectionReason, status: "queued", promptVersion: input.promptVersion, provider: input.provider, requestedModel: input.requestedModel, actualModel: null, contextManifest: JSON.stringify(input.contextManifest), summary: null, areasReviewed: "[]", limitations: "[]", hypothesisCount: 0, inputTokens: null, outputTokens: null, totalTokens: null, durationMs: null, requestId: null, error: null, createdAt: new Date(), startedAt: null, completedAt: null };
  database.orm.insert(securityReviewerRuns).values(row).run(); return row;
}
export function updateSecurityReviewerRun(database: DatabaseClient, id: string, status: ReviewRunStatus, fields: Partial<Pick<SecurityReviewerRunRow, "actualModel" | "summary" | "areasReviewed" | "limitations" | "hypothesisCount" | "inputTokens" | "outputTokens" | "totalTokens" | "durationMs" | "requestId" | "error">> = {}): void {
  database.orm.update(securityReviewerRuns).set({ status, ...fields, ...(status === "running" ? { startedAt: new Date() } : {}), ...(["completed", "failed"].includes(status) ? { completedAt: new Date() } : {}) }).where(eq(securityReviewerRuns.id, id)).run();
}
export function listSecurityReviewerRuns(database: DatabaseClient, planId: string): SecurityReviewerRunRow[] { return database.orm.select().from(securityReviewerRuns).where(eq(securityReviewerRuns.planId, planId)).orderBy(securityReviewerRuns.createdAt, securityReviewerRuns.reviewerId).all(); }
export function getSecurityReviewerRun(database: DatabaseClient, id: string): SecurityReviewerRunRow | undefined { return database.orm.select().from(securityReviewerRuns).where(eq(securityReviewerRuns.id, id)).get(); }

export type PersistHypothesisInput = Omit<VulnerabilityHypothesisRow, "id" | "createdAt" | "updatedAt" | "status">;
export function insertVulnerabilityHypotheses(database: DatabaseClient, input: PersistHypothesisInput[]): VulnerabilityHypothesisRow[] {
  const now = new Date(); const rows: VulnerabilityHypothesisRow[] = input.map((item) => ({ ...item, id: randomUUID(), status: "candidate", createdAt: now, updatedAt: now }));
  if (rows.length) database.orm.insert(vulnerabilityHypotheses).values(rows).run(); return rows;
}
export function getVulnerabilityHypothesis(database: DatabaseClient, id: string): VulnerabilityHypothesisRow | undefined { return database.orm.select().from(vulnerabilityHypotheses).where(eq(vulnerabilityHypotheses.id, id)).get(); }
export function updateVulnerabilityHypothesisStatus(database: DatabaseClient, id: string, status: Exclude<HypothesisStatus, "verified">): VulnerabilityHypothesisRow | undefined {
  if ((status as HypothesisStatus) === "verified") throw new Error("Verified status requires confirmed dynamic evidence.");
  database.orm.update(vulnerabilityHypotheses).set({ status, updatedAt: new Date() }).where(eq(vulnerabilityHypotheses.id, id)).run(); return getVulnerabilityHypothesis(database, id);
}

function requireHypothesisVerificationRun(database: DatabaseClient, id: string): HypothesisVerificationRunRow {
  const run = getHypothesisVerificationRun(database, id);
  if (!run) throw new Error("Hypothesis verification run not found.");
  return run;
}

export function createHypothesisVerificationRun(database: DatabaseClient, input: CreateHypothesisVerificationRunInput): HypothesisVerificationRunRow {
  const parsed = createHypothesisVerificationRunSchema.parse(input);
  const hypothesis = getVulnerabilityHypothesis(database, parsed.hypothesisId);
  if (!hypothesis) throw new Error("Vulnerability hypothesis not found.");
  if (hypothesis.scanId !== parsed.scanId) throw new Error("Verification scan does not match the hypothesis scan.");
  const scan = getScan(database, parsed.scanId);
  if (!scan || scan.resolvedCommit !== parsed.resolvedCommit) throw new Error("Verification commit does not match the resolved scan commit.");
  const row: HypothesisVerificationRunRow = {
    id: randomUUID(), hypothesisId: parsed.hypothesisId, scanId: parsed.scanId, resolvedCommit: parsed.resolvedCommit,
    status: "queued", outcome: null, verifierId: parsed.verifierId, toolName: parsed.toolName, toolVersion: parsed.toolVersion,
    verificationStrategy: JSON.stringify(parsed.verificationStrategy), resultSummary: null, testCount: 0, passedTestCount: 0, failedTestCount: 0,
    stdoutSummary: "", stderrSummary: "", dynamicEvidence: "[]", error: null, createdAt: new Date(), startedAt: null, completedAt: null, durationMs: null,
  };
  database.orm.insert(hypothesisVerificationRuns).values(row).run();
  return row;
}

export function markHypothesisVerificationRunRunning(database: DatabaseClient, id: string): HypothesisVerificationRunRow {
  const run = requireHypothesisVerificationRun(database, id); assertVerificationRunTransition(run.status, "running");
  database.orm.update(hypothesisVerificationRuns).set({ status: "running", startedAt: new Date() }).where(eq(hypothesisVerificationRuns.id, id)).run();
  return requireHypothesisVerificationRun(database, id);
}

export function completeHypothesisVerificationRun(database: DatabaseClient, id: string, input: CompleteHypothesisVerificationRunInput): HypothesisVerificationRunRow {
  const run = requireHypothesisVerificationRun(database, id); assertVerificationRunTransition(run.status, "completed");
  const parsed = completeHypothesisVerificationRunSchema.parse(input); const completedAt = new Date();
  database.sqlite.transaction(() => {
    database.orm.update(hypothesisVerificationRuns).set({ status: "completed", outcome: parsed.outcome, resultSummary: parsed.resultSummary, durationMs: parsed.durationMs, testCount: parsed.testCount, passedTestCount: parsed.passedTestCount, failedTestCount: parsed.failedTestCount, stdoutSummary: parsed.stdoutSummary, stderrSummary: parsed.stderrSummary, dynamicEvidence: JSON.stringify(parsed.dynamicEvidence), error: null, completedAt }).where(eq(hypothesisVerificationRuns.id, id)).run();
    if (parsed.outcome === "confirmed" && parsed.dynamicEvidence.some((item) => item.direction === "supports")) verifyHypothesisFromDynamicEvidence(database, id);
  })();
  return requireHypothesisVerificationRun(database, id);
}

export function failHypothesisVerificationRun(database: DatabaseClient, id: string, input: FailHypothesisVerificationRunInput): HypothesisVerificationRunRow {
  const run = requireHypothesisVerificationRun(database, id); assertVerificationRunTransition(run.status, "failed");
  const parsed = failHypothesisVerificationRunSchema.parse(input);
  database.orm.update(hypothesisVerificationRuns).set({ status: "failed", outcome: null, durationMs: parsed.durationMs, stdoutSummary: parsed.stdoutSummary, stderrSummary: parsed.stderrSummary, error: parsed.error, completedAt: new Date() }).where(eq(hypothesisVerificationRuns.id, id)).run();
  return requireHypothesisVerificationRun(database, id);
}

export function getHypothesisVerificationRun(database: DatabaseClient, id: string): HypothesisVerificationRunRow | undefined { return database.orm.select().from(hypothesisVerificationRuns).where(eq(hypothesisVerificationRuns.id, id)).get(); }
export function listHypothesisVerificationRuns(database: DatabaseClient, hypothesisId: string): HypothesisVerificationRunRow[] { return database.orm.select().from(hypothesisVerificationRuns).where(eq(hypothesisVerificationRuns.hypothesisId, hypothesisId)).orderBy(desc(hypothesisVerificationRuns.createdAt), desc(sql`rowid`)).all(); }
export function getLatestHypothesisVerificationRun(database: DatabaseClient, hypothesisId: string): HypothesisVerificationRunRow | undefined { return listHypothesisVerificationRuns(database, hypothesisId)[0]; }

export function verifyHypothesisFromDynamicEvidence(database: DatabaseClient, verificationRunId: string): VulnerabilityHypothesisRow {
  const run = requireHypothesisVerificationRun(database, verificationRunId);
  if (run.status !== "completed" || run.outcome !== "confirmed") throw new Error("Only a completed, confirmed verification run can verify a hypothesis.");
  const evidence = dynamicEvidenceSchema.array().parse(JSON.parse(run.dynamicEvidence)) as DynamicEvidence[];
  if (!evidence.some((item) => item.direction === "supports")) throw new Error("Verified status requires supporting dynamic evidence.");
  database.orm.update(vulnerabilityHypotheses).set({ status: "verified", updatedAt: new Date() }).where(eq(vulnerabilityHypotheses.id, run.hypothesisId)).run();
  const hypothesis = getVulnerabilityHypothesis(database, run.hypothesisId);
  if (!hypothesis) throw new Error("Vulnerability hypothesis not found.");
  return hypothesis;
}

export type HypothesisFilters = { scanId?: string; severity?: Severity; category?: string; reviewerId?: string; status?: HypothesisStatus; minimumConfidence?: number; evidenceClass?: string; includeHistory?: boolean };
export type RankedHypothesis = VulnerabilityHypothesisRow & { priorityScore: number; groupConfidenceScore: number; evidenceClasses: string[]; groupId: string | null };
export function listVulnerabilityHypotheses(database: DatabaseClient, filters: HypothesisFilters = {}): RankedHypothesis[] {
  const plans = filters.includeHistory ? database.orm.select().from(securityReviewPlans).all() : database.orm.select().from(securityReviewPlans).where(eq(securityReviewPlans.isLatest, true)).all();
  const planIds = plans.filter((plan) => !filters.scanId || plan.scanId === filters.scanId).map((plan) => plan.id); if (!planIds.length) return [];
  const runs = database.orm.select().from(securityReviewerRuns).where(inArray(securityReviewerRuns.planId, planIds)).all(); const runIds = runs.map((run) => run.id); if (!runIds.length) return [];
  const rows = database.orm.select().from(vulnerabilityHypotheses).where(inArray(vulnerabilityHypotheses.reviewerRunId, runIds)).all();
  const memberships = database.orm.select().from(hypothesisGroupMembers).all(); const groupRows = database.orm.select().from(hypothesisGroups).where(inArray(hypothesisGroups.planId, planIds)).all(); const groupsById = new Map(groupRows.map((group) => [group.id, group])); const groupByHypothesis = new Map(memberships.map((member) => [member.hypothesisId, groupsById.get(member.groupId)]));
  return rows.map((row) => { const group = groupByHypothesis.get(row.id); return { ...row, priorityScore: group?.priorityScore ?? 0, groupConfidenceScore: group?.confidenceScore ?? row.confidence, evidenceClasses: group ? JSON.parse(group.evidenceClasses) as string[] : ["semantic"], groupId: group?.id ?? null }; }).filter((row) => (!filters.scanId || row.scanId === filters.scanId) && (!filters.severity || row.severity === filters.severity) && (!filters.category || row.category === filters.category) && (!filters.reviewerId || row.reviewerId === filters.reviewerId) && (!filters.status || row.status === filters.status) && (filters.minimumConfidence === undefined || row.confidence >= filters.minimumConfidence) && (!filters.evidenceClass || row.evidenceClasses.includes(filters.evidenceClass))).sort((a, b) => b.priorityScore - a.priorityScore || b.confidence - a.confidence || a.title.localeCompare(b.title));
}
export function listHypothesesForInvestigation(database: DatabaseClient, investigationId: string): RankedHypothesis[] { return listVulnerabilityHypotheses(database).filter((item) => { try { return (JSON.parse(item.relatedInvestigationIds) as string[]).includes(investigationId); } catch { return false; } }); }
export function countHypothesesByInvariant(database: DatabaseClient, invariantId: string): number { return listVulnerabilityHypotheses(database).filter((item) => { try { return (JSON.parse(item.violatedInvariantIds) as string[]).includes(invariantId); } catch { return false; } }).length; }

export function correlateAndPersistHypotheses(database: DatabaseClient, planId: string): HypothesisGroupRow[] {
  const plan = getSecurityReviewPlan(database, planId); if (!plan) throw new Error("Security review plan not found.");
  const runs = listSecurityReviewerRuns(database, planId); const runIds = runs.map((run) => run.id); const rows = runIds.length ? database.orm.select().from(vulnerabilityHypotheses).where(inArray(vulnerabilityHypotheses.reviewerRunId, runIds)).all() : [];
  const candidates = correlateHypotheses(rows.map((row) => ({ id: row.id, reviewerId: row.reviewerId, category: row.category, severity: row.severity, confidence: row.confidence, rootCause: row.rootCause, evidence: JSON.parse(row.evidence) as ValidatedEvidence[], violatedInvariantIds: JSON.parse(row.violatedInvariantIds) as string[], relatedInvestigationIds: JSON.parse(row.relatedInvestigationIds) as string[] })));
  const now = new Date(); const groups: HypothesisGroupRow[] = candidates.map((candidate) => ({ id: randomUUID(), planId, scanId: plan.scanId, fingerprint: candidate.fingerprint, priorityScore: candidate.priorityScore, confidenceScore: candidate.confidenceScore, evidenceClasses: JSON.stringify(candidate.evidenceClasses), reasons: JSON.stringify(candidate.reasons), createdAt: now }));
  database.sqlite.transaction(() => { database.orm.delete(hypothesisGroups).where(eq(hypothesisGroups.planId, planId)).run(); if (groups.length) database.orm.insert(hypothesisGroups).values(groups).run(); for (let index = 0; index < groups.length; index++) database.orm.insert(hypothesisGroupMembers).values(candidates[index].memberIds.map((hypothesisId) => ({ groupId: groups[index].id, hypothesisId }))).run(); })(); return groups;
}

export function dashboardStats(database: DatabaseClient) {
  const scanRows = database.orm.select({ status: scans.status, count: sql<number>`count(*)` }).from(scans).groupBy(scans.status).all();
  const severityRows = database.orm.select({ severity: findings.severity, count: sql<number>`count(*)` }).from(findings).groupBy(findings.severity).all();
  const sourceRows = database.orm.select({ source: findings.source, count: sql<number>`count(*)` }).from(findings).groupBy(findings.source).all();
  const investigationRows = database.orm.select({ status: investigations.status, severity: investigations.severity, count: sql<number>`count(*)` }).from(investigations).groupBy(investigations.status, investigations.severity).all();
  return {
    totalScans: scanRows.reduce((sum, item) => sum + item.count, 0),
    completedScans: scanRows.find((item) => item.status === "completed")?.count ?? 0,
    failedScans: scanRows.find((item) => item.status === "failed")?.count ?? 0,
    totalFindings: severityRows.reduce((sum, item) => sum + item.count, 0),
    bySeverity: Object.fromEntries(severityRows.map((item) => [item.severity, item.count])) as Partial<Record<Severity, number>>,
    bySource: Object.fromEntries(sourceRows.map((item) => [item.source, item.count])) as Record<string, number>,
    totalInvestigations: investigationRows.reduce((sum, item) => sum + item.count, 0),
    highCriticalCandidates: investigationRows.filter((item) => item.status === "candidate" && (item.severity === "critical" || item.severity === "high")).reduce((sum, item) => sum + item.count, 0),
    investigating: investigationRows.filter((item) => item.status === "investigating").reduce((sum, item) => sum + item.count, 0),
    verified: investigationRows.filter((item) => item.status === "verified").reduce((sum, item) => sum + item.count, 0),
    rejected: investigationRows.filter((item) => item.status === "rejected").reduce((sum, item) => sum + item.count, 0),
  };
}
