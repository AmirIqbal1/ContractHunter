import Link from "next/link";
import { investigationStatuses, severities, type InvestigationStatus, type Severity } from "@contracthunter/core";
import { getDatabase, listInvestigations, listScans } from "@contracthunter/db";
import { InvestigationStatusBadge, SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";
type Query = { scan?: string; severity?: string; status?: string; confidence?: string; sources?: string };

export default async function InvestigationsPage({ searchParams }: { searchParams: Promise<Query> }) {
  const query = await searchParams;
  const database = getDatabase();
  const scans = listScans(database);
  const scanId = query.scan && scans.some((scan) => scan.id === query.scan) ? query.scan : undefined;
  const severity = severities.includes(query.severity as Severity) ? query.severity as Severity : undefined;
  const status = investigationStatuses.includes(query.status as InvestigationStatus) ? query.status as InvestigationStatus : undefined;
  const minimumConfidence = query.confidence && /^\d+$/.test(query.confidence) ? Math.min(100, Number(query.confidence)) : undefined;
  const sourceCount = query.sources && /^\d+$/.test(query.sources) ? Math.max(1, Number(query.sources)) : undefined;
  const results = listInvestigations(database, { scanId, severity, status, minimumConfidence, sourceCount });
  return <>
    <header className="page-head"><div><div className="eyebrow">Prioritised review queue</div><h1>Investigations</h1><p className="subhead">Correlated scanner evidence ranked for human review. Static-analysis candidates are never auto-verified.</p></div></header>
    <form className="filter-row investigation-filters">
      <select name="scan" defaultValue={scanId ?? ""} aria-label="Filter by scan"><option value="">All hunts</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.repositoryName} · {scan.id.slice(0, 8)}</option>)}</select>
      <select name="severity" defaultValue={severity ?? ""} aria-label="Filter by severity"><option value="">All severities</option>{severities.map((item) => <option key={item}>{item}</option>)}</select>
      <select name="status" defaultValue={status ?? ""} aria-label="Filter by status"><option value="">All statuses</option>{investigationStatuses.map((item) => <option key={item}>{item}</option>)}</select>
      <input name="confidence" type="number" min="0" max="100" defaultValue={minimumConfidence} placeholder="Min confidence" aria-label="Minimum confidence" />
      <select name="sources" defaultValue={sourceCount ?? ""} aria-label="Minimum scanner sources"><option value="">Any source count</option><option value="2">2+ scanners</option></select>
      <button className="button">FILTER</button>
    </form>
    <div className="table-wrap"><table><thead><tr><th>Priority</th><th>Severity</th><th>Investigation</th><th>Location</th><th>Confidence</th><th>Sources</th><th>Status</th></tr></thead><tbody>{results.map((item) => <tr key={item.id}><td><strong className="mono">{item.priorityScore}</strong></td><td><SeverityBadge value={item.severity} /></td><td className="finding-title"><Link className="repo" href={`/investigations/${item.id}`}>{item.title}</Link><div className="muted" style={{ fontSize: 11, marginTop: 5 }}>{item.category}</div></td><td className="mono">{item.primaryFilePath ?? "—"}{item.startLine ? `:${item.startLine}` : ""}</td><td>{item.confidenceScore}%</td><td>{item.sourceCount}</td><td><InvestigationStatusBadge value={item.status} /></td></tr>)}{results.length === 0 && <tr><td className="empty" colSpan={7}>No investigations match these filters.</td></tr>}</tbody></table></div>
  </>;
}
