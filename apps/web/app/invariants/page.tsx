import Link from "next/link";
import { invariantCategories, invariantStatuses, invariantTestabilities, severities, type InvariantCategory, type InvariantStatus, type InvariantTestability, type Severity } from "@contracthunter/core";
import { countHypothesesByInvariant, getDatabase, listInvariants, listScans } from "@contracthunter/db";
import { InvariantStatusBadge, SeverityBadge } from "@/components/badges";

export const dynamic = "force-dynamic";
type Query = { scan?: string; category?: string; severity?: string; status?: string; testability?: string };
const jsonList = (value: string): string[] => { try { const parsed = JSON.parse(value); return Array.isArray(parsed) ? parsed : []; } catch { return []; } };

export default async function InvariantsPage({ searchParams }: { searchParams: Promise<Query> }) {
  const query = await searchParams; const database = getDatabase(); const scans = listScans(database);
  const scanId = query.scan && scans.some((scan) => scan.id === query.scan) ? query.scan : undefined;
  const category = invariantCategories.includes(query.category as InvariantCategory) ? query.category as InvariantCategory : undefined;
  const severity = severities.includes(query.severity as Severity) ? query.severity as Severity : undefined;
  const status = invariantStatuses.includes(query.status as InvariantStatus) ? query.status as InvariantStatus : undefined;
  const testability = invariantTestabilities.includes(query.testability as InvariantTestability) ? query.testability as InvariantTestability : undefined;
  const results = listInvariants(database, { scanId, category, severity, status, testability });
  return <><header className="page-head"><div><div className="eyebrow">AI-proposed security properties</div><h1>Invariants</h1><p className="subhead">Properties the protocol should preserve. These are hypotheses, not verified vulnerabilities.</p></div></header>
    <form className="filter-row investigation-filters"><select name="scan" defaultValue={scanId ?? ""}><option value="">All hunts</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.repositoryName}</option>)}</select><select name="category" defaultValue={category ?? ""}><option value="">All categories</option>{invariantCategories.map((item) => <option key={item}>{item}</option>)}</select><select name="severity" defaultValue={severity ?? ""}><option value="">All impacts</option>{severities.map((item) => <option key={item}>{item}</option>)}</select><select name="status" defaultValue={status ?? ""}><option value="">All statuses</option>{invariantStatuses.map((item) => <option key={item}>{item}</option>)}</select><select name="testability" defaultValue={testability ?? ""}><option value="">All testability</option>{invariantTestabilities.map((item) => <option key={item}>{item}</option>)}</select><button className="button">FILTER</button></form>
    <div className="table-wrap"><table><thead><tr><th>Impact if violated</th><th>Invariant</th><th>Category</th><th>Testability</th><th>Confidence</th><th>Potential violations</th><th>Contracts</th><th>Status</th></tr></thead><tbody>{results.map((item) => <tr key={item.id}><td><SeverityBadge value={item.severityIfViolated} /></td><td className="finding-title"><Link className="repo" href={`/invariants/${item.id}`}>{item.title}</Link></td><td>{item.category}</td><td>{item.testability}</td><td>{item.confidence}%</td><td>{countHypothesesByInvariant(database, item.id)}</td><td className="mono">{jsonList(item.relatedContracts).join(", ") || "—"}</td><td><InvariantStatusBadge value={item.status} /></td></tr>)}{!results.length && <tr><td colSpan={8} className="empty">No invariants match these filters.</td></tr>}</tbody></table></div></>;
}
