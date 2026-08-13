import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { findingStatuses, frameworks, scannerStatuses, scanDepths, scanStatuses, severities } from "@contracthunter/core";

export const scans = sqliteTable("scans", {
  id: text("id").primaryKey(),
  repositoryUrl: text("repository_url").notNull(),
  repositoryName: text("repository_name").notNull(),
  requestedRef: text("requested_ref"),
  resolvedCommit: text("resolved_commit"),
  status: text("status", { enum: scanStatuses }).notNull(),
  framework: text("framework", { enum: frameworks }).notNull(),
  depth: text("depth", { enum: scanDepths }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  startedAt: integer("started_at", { mode: "timestamp" }),
  completedAt: integer("completed_at", { mode: "timestamp" }),
  error: text("error"),
  scannerName: text("scanner_name"),
  scannerStatus: text("scanner_status", { enum: scannerStatuses }).notNull(),
  scannerDurationMs: integer("scanner_duration_ms"),
});

export const findings = sqliteTable("findings", {
  id: text("id").primaryKey(),
  scanId: text("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  severity: text("severity", { enum: severities }).notNull(),
  confidence: integer("confidence").notNull(),
  source: text("source").notNull(),
  detectorId: text("detector_id"),
  fingerprint: text("fingerprint").notNull().unique(),
  contract: text("contract"),
  functionName: text("function_name"),
  filePath: text("file_path"),
  startLine: integer("start_line"),
  endLine: integer("end_line"),
  rootCause: text("root_cause").notNull(),
  attackScenario: text("attack_scenario").notNull(),
  impact: text("impact").notNull(),
  evidence: text("evidence").notNull(),
  status: text("status", { enum: findingStatuses }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export type ScanRow = typeof scans.$inferSelect;
export type FindingRow = typeof findings.$inferSelect;
