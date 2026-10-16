import type { DatabaseClient } from "@contracthunter/db";
import { loadImpactOverlay } from "./impact-overlay-server";

/** Bounded selectors only. Every selected execution is revalidated by loadImpactOverlay. */
export function listImpactExecutionIds(database: DatabaseClient, scanId: string,
  subject?: { type: "finding" | "hypothesis" | "investigation"; id: string }): string[] {
  const clause = subject?.type === "finding" ? "AND a.finding_id = ?" :
    subject?.type === "hypothesis" ? "AND a.hypothesis_id = ?" :
    subject?.type === "investigation" ?
      "AND a.finding_id IN (SELECT finding_id FROM investigation_findings WHERE investigation_id = ?)" : "";
  const rows = database.sqlite.prepare(`SELECT e.id FROM impact_poc_executions e
    JOIN impact_poc_artifacts a ON a.id = e.artifact_id
    LEFT JOIN findings f ON f.id = a.finding_id
    LEFT JOIN vulnerability_hypotheses h ON h.id = a.hypothesis_id
    WHERE a.review_state = 'reviewed' AND e.status IN ('completed','failed','cancelled')
    AND (f.scan_id = ? OR h.scan_id = ?) ${clause}
    ORDER BY e.created_at DESC, e.id DESC LIMIT 32`).all(scanId, scanId,
      ...(subject ? [subject.id] : [])) as Array<{ id: string }>;
  return rows.map((row) => row.id);
}

export function selectImpactOverlay(database: DatabaseClient, scanId: string, ids: readonly string[], requested?: string) {
  const id = requested ? ids.includes(requested) ? requested : null : ids[0];
  if (!id) return null;
  return loadImpactOverlay(database, scanId, id);
}
