import Link from "next/link";
import { notFound } from "next/navigation";
import { getDatabase, getInvestigation, getScan, listInvestigationFindings } from "@contracthunter/db";
import { SeverityBadge } from "@/components/badges";
import { InvestigationStatusControl } from "@/components/investigation-status-control";
import { formatDate } from "@/components/format";

export const dynamic = "force-dynamic";
const parseReasons = (value: string): string[] => { try { const parsed = JSON.parse(value); return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : []; } catch { return []; } };

export default async function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const database = getDatabase();
  const investigation = getInvestigation(database, (await params).id);
  if (!investigation) notFound();
  const evidence = listInvestigationFindings(database, investigation.id);
  const scan = getScan(database, investigation.scanId);
  const reasons = parseReasons(investigation.reasons);
  return <article className="article">
    <header className="page-head"><div><div className="eyebrow">Investigation / priority {investigation.priorityScore}</div><h1>{investigation.title}</h1><p className="subhead">Created {formatDate(investigation.createdAt)} · <Link className="muted-link" href={`/hunts/${investigation.scanId}`}>{scan?.repositoryName ?? "View hunt"}</Link></p></div><SeverityBadge value={investigation.severity} /></header>
    <section className="card"><dl className="details"><div className="detail"><dt>Confidence</dt><dd>{investigation.confidenceScore}% <span className="muted">(static evidence)</span></dd></div><div className="detail"><dt>Category</dt><dd>{investigation.category}</dd></div><div className="detail"><dt>Independent scanners</dt><dd>{investigation.sourceCount}</dd></div><div className="detail"><dt>Review status</dt><dd><InvestigationStatusControl id={investigation.id} status={investigation.status} /></dd></div><div className="detail" style={{ gridColumn: "1 / -1" }}><dt>Primary location</dt><dd className="mono">{investigation.primaryFilePath ?? "—"}{investigation.startLine ? `:${investigation.startLine}${investigation.endLine && investigation.endLine !== investigation.startLine ? `–${investigation.endLine}` : ""}` : ""} · {investigation.primaryContract ?? "—"}.{investigation.primaryFunction ?? "—"}</dd></div></dl></section>
    <section className="article-section"><h2>Why these findings were correlated</h2><ul className="reason-list">{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></section>
    <section className="section"><div className="section-head"><h2>Raw scanner evidence</h2><span className="muted mono" style={{ fontSize: 11 }}>{evidence.length} RECORDS</span></div><div className="table-wrap"><table><thead><tr><th>Scanner</th><th>Detector</th><th>Finding</th><th>Location</th><th>Scanner confidence</th></tr></thead><tbody>{evidence.map((finding) => <tr key={finding.id}><td><span className="badge gray">{finding.source}</span></td><td className="mono">{finding.detectorId ?? "—"}</td><td className="finding-title"><Link className="repo" href={`/findings/${finding.id}`}>{finding.title}</Link></td><td className="mono">{finding.filePath ?? "—"}{finding.startLine ? `:${finding.startLine}` : ""}</td><td>{finding.source === "aderyn" ? <span className="muted">Not supplied by Aderyn</span> : `${finding.confidence}%`}</td></tr>)}</tbody></table></div></section>
  </article>;
}
