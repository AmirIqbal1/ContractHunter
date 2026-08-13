import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import type { CompilerStatus, CreateScanInput, FindingStatus, NewFinding, ScannerStatus, ScanStatus, Severity } from "@contracthunter/core";
import { assertTransition, findingSchema, loadConfig, scanSchema } from "@contracthunter/core";
import { findings, scans, type FindingRow, type ScanRow } from "./schema";

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
      compiler_status TEXT NOT NULL DEFAULT 'pending', compiler_error TEXT
    );
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      title TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER NOT NULL, source TEXT NOT NULL,
      detector_id TEXT, fingerprint TEXT,
      contract TEXT, function_name TEXT, file_path TEXT, start_line INTEGER, end_line INTEGER,
      root_cause TEXT NOT NULL, attack_scenario TEXT NOT NULL, impact TEXT NOT NULL, evidence TEXT NOT NULL,
      status TEXT NOT NULL, created_at INTEGER NOT NULL
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
  const findingColumns = new Set((sqlite.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>).map((column) => column.name));
  if (!findingColumns.has("detector_id")) sqlite.exec("ALTER TABLE findings ADD COLUMN detector_id TEXT");
  if (!findingColumns.has("fingerprint")) sqlite.exec("ALTER TABLE findings ADD COLUMN fingerprint TEXT");
  sqlite.exec(`
    CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS findings_filters_idx ON findings(severity, status, source);
    CREATE UNIQUE INDEX IF NOT EXISTS findings_fingerprint_idx ON findings(fingerprint) WHERE fingerprint IS NOT NULL;
    CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans(created_at);
  `);
  const orm = drizzle(sqlite, { schema: { scans, findings } });
  return { sqlite, orm };
}

let singleton: DatabaseClient | undefined;
export function getDatabase(): DatabaseClient {
  if (!singleton) singleton = createDatabase(loadConfig().DATABASE_PATH);
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

export function markActiveScansInterrupted(database: DatabaseClient): number {
  const active: ScanStatus[] = ["queued", "cloning", "detecting", "scanning"];
  return database.orm.update(scans).set({ status: "failed", scannerStatus: "failed", compilerStatus: "failed", completedAt: new Date(), error: "Scan interrupted by application restart." }).where(inArray(scans.status, active)).run().changes;
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

export function dashboardStats(database: DatabaseClient) {
  const scanRows = database.orm.select({ status: scans.status, count: sql<number>`count(*)` }).from(scans).groupBy(scans.status).all();
  const severityRows = database.orm.select({ severity: findings.severity, count: sql<number>`count(*)` }).from(findings).groupBy(findings.severity).all();
  return {
    totalScans: scanRows.reduce((sum, item) => sum + item.count, 0),
    completedScans: scanRows.find((item) => item.status === "completed")?.count ?? 0,
    failedScans: scanRows.find((item) => item.status === "failed")?.count ?? 0,
    totalFindings: severityRows.reduce((sum, item) => sum + item.count, 0),
    bySeverity: Object.fromEntries(severityRows.map((item) => [item.severity, item.count])) as Partial<Record<Severity, number>>,
  };
}
