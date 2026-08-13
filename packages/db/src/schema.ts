import { integer, primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { aiAnalysisStatuses, compilerStatuses, coverageStatuses, dependencyStatuses, findingStatuses, frameworks, invariantCategories, invariantStatuses, invariantTestabilities, investigationStatuses, scannerStatuses, scanDepths, scanStatuses, severities, vulnerabilityCategories } from "@contracthunter/core";

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
  compilerConstraints: text("compiler_constraints"),
  compilerVersions: text("compiler_versions"),
  compilerDetectionSource: text("compiler_detection_source", { enum: ["foundry-config", "pragma"] }),
  compilerStatus: text("compiler_status", { enum: compilerStatuses }).notNull(),
  compilerError: text("compiler_error"),
  dependencyStatus: text("dependency_status", { enum: dependencyStatuses }).notNull(),
  dependencyMetadata: text("dependency_metadata"),
  dependencyError: text("dependency_error"),
  aiStatus: text("ai_status", { enum: aiAnalysisStatuses }).notNull(),
  aiError: text("ai_error"),
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

export const scanScanners = sqliteTable("scan_scanners", {
  scanId: text("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  scannerId: text("scanner_id").notNull(),
  scannerName: text("scanner_name").notNull(),
  status: text("status", { enum: scannerStatuses }).notNull(),
  findingCount: integer("finding_count").notNull().default(0),
  durationMs: integer("duration_ms"),
  error: text("error"),
  version: text("version"),
}, (table) => [primaryKey({ columns: [table.scanId, table.scannerId] })]);

export const investigations = sqliteTable("investigations", {
  id: text("id").primaryKey(),
  scanId: text("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  fingerprint: text("fingerprint").notNull().unique(),
  title: text("title").notNull(),
  severity: text("severity", { enum: severities }).notNull(),
  category: text("category", { enum: vulnerabilityCategories }).notNull(),
  priorityScore: integer("priority_score").notNull(),
  confidenceScore: integer("confidence_score").notNull(),
  status: text("status", { enum: investigationStatuses }).notNull(),
  primaryFilePath: text("primary_file_path"),
  primaryContract: text("primary_contract"),
  primaryFunction: text("primary_function"),
  startLine: integer("start_line"),
  endLine: integer("end_line"),
  sourceCount: integer("source_count").notNull(),
  reasons: text("reasons").notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const investigationFindings = sqliteTable("investigation_findings", {
  investigationId: text("investigation_id").notNull().references(() => investigations.id, { onDelete: "cascade" }),
  findingId: text("finding_id").notNull().references(() => findings.id, { onDelete: "cascade" }),
}, (table) => [primaryKey({ columns: [table.investigationId, table.findingId] })]);

export const protocolAnalyses = sqliteTable("protocol_analyses", {
  id: text("id").primaryKey(),
  scanId: text("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  provider: text("provider").notNull(), requestedModel: text("requested_model").notNull(), actualModel: text("actual_model"), promptVersion: text("prompt_version").notNull(),
  protocolName: text("protocol_name").notNull(), protocolTypes: text("protocol_types").notNull(), summary: text("summary").notNull(), architectureSummary: text("architecture_summary").notNull(), confidence: integer("confidence").notNull(),
  coverageStatus: text("coverage_status", { enum: coverageStatuses }).notNull(), contextManifest: text("context_manifest").notNull(), assets: text("assets").notNull(), roles: text("roles").notNull(), entryPoints: text("entry_points").notNull(), criticalState: text("critical_state").notNull(), externalDependencies: text("external_dependencies").notNull(), flows: text("flows").notNull(), trustAssumptions: text("trust_assumptions").notNull(), limitations: text("limitations").notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(), durationMs: integer("duration_ms").notNull(), inputTokens: integer("input_tokens"), outputTokens: integer("output_tokens"), totalTokens: integer("total_tokens"), requestId: text("request_id"), isLatest: integer("is_latest", { mode: "boolean" }).notNull(),
});

export const invariants = sqliteTable("invariants", {
  id: text("id").primaryKey(), analysisId: text("analysis_id").notNull().references(() => protocolAnalyses.id, { onDelete: "cascade" }), scanId: text("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  title: text("title").notNull(), description: text("description").notNull(), category: text("category", { enum: invariantCategories }).notNull(), severityIfViolated: text("severity_if_violated", { enum: severities }).notNull(), confidence: integer("confidence").notNull(), rationale: text("rationale").notNull(), relatedContracts: text("related_contracts").notNull(), relatedFunctions: text("related_functions").notNull(), relatedState: text("related_state").notNull(), sourceEvidence: text("source_evidence").notNull(), testability: text("testability", { enum: invariantTestabilities }).notNull(), status: text("status", { enum: invariantStatuses }).notNull(), createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export type ScanRow = typeof scans.$inferSelect;
export type FindingRow = typeof findings.$inferSelect;
export type ScanScannerRow = typeof scanScanners.$inferSelect;
export type InvestigationRow = typeof investigations.$inferSelect;
export type ProtocolAnalysisRow = typeof protocolAnalyses.$inferSelect;
export type InvariantRow = typeof invariants.$inferSelect;
