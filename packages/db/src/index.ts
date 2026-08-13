import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { and, desc, eq, gte, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import type { CompilerStatus, CreateScanInput, DependencyStatus, FindingStatus, InvestigationStatus, NewFinding, ScannerStatus, ScanStatus, Severity } from "@contracthunter/core";
import { assertTransition, buildInvestigations, findingSchema, investigationSchema, loadConfig, scanSchema } from "@contracthunter/core";
import { findings, investigationFindings, investigations, scans, scanScanners, type FindingRow, type InvestigationRow, type ScanRow, type ScanScannerRow } from "./schema";

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
      dependency_status TEXT NOT NULL DEFAULT 'pending', dependency_metadata TEXT, dependency_error TEXT
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
  `);
  const orm = drizzle(sqlite, { schema: { scans, findings, scanScanners, investigations, investigationFindings } });
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

export function markActiveScansInterrupted(database: DatabaseClient): number {
  const active: ScanStatus[] = ["queued", "cloning", "detecting", "preparing_dependencies", "preparing_compiler", "scanning"];
  const result = database.orm.update(scans).set({ status: "failed", scannerStatus: "failed", compilerStatus: "failed", dependencyStatus: "failed", completedAt: new Date(), error: "Scan interrupted by application restart." }).where(inArray(scans.status, active)).run().changes;
  database.sqlite.prepare("UPDATE scan_scanners SET status = 'failed', error = 'Scan interrupted by application restart.' WHERE status IN ('pending', 'available', 'running')").run();
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
