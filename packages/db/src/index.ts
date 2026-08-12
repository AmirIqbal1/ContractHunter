import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import type { CreateScanInput, FindingStatus, NewFinding, ScanStatus, Severity } from "@contracthunter/core";
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
      depth TEXT NOT NULL, created_at INTEGER NOT NULL, started_at INTEGER, completed_at INTEGER, error TEXT
    );
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      title TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER NOT NULL, source TEXT NOT NULL,
      contract TEXT, function_name TEXT, file_path TEXT, start_line INTEGER, end_line INTEGER,
      root_cause TEXT NOT NULL, attack_scenario TEXT NOT NULL, impact TEXT NOT NULL, evidence TEXT NOT NULL,
      status TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS findings_scan_id_idx ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS findings_filters_idx ON findings(severity, status, source);
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

export function markActiveScansInterrupted(database: DatabaseClient): number {
  const active: ScanStatus[] = ["queued", "cloning", "detecting", "scanning"];
  return database.orm.update(scans).set({ status: "failed", completedAt: new Date(), error: "Scan interrupted by application restart." }).where(inArray(scans.status, active)).run().changes;
}

export function insertFindings(database: DatabaseClient, scanId: string, input: NewFinding[]): FindingRow[] {
  const rows = input.map((finding) => {
    const row = { ...finding, id: randomUUID(), scanId, createdAt: new Date() };
    findingSchema.parse(row);
    return row;
  });
  if (rows.length) database.orm.insert(findings).values(rows).run();
  return rows;
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
