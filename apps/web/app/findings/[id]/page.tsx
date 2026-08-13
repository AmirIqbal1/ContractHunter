import Link from "next/link";
import { notFound } from "next/navigation";
import { getDatabase, getFinding, getScan } from "@contracthunter/db";
import { FindingStatusBadge, SeverityBadge } from "@/components/badges";
import { formatDate } from "@/components/format";

export const dynamic = "force-dynamic";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const finding = getFinding(getDatabase(), (await params).id);
  if (!finding) notFound();
  const scan = getScan(getDatabase(), finding.scanId);
  return <article className="article">
    <header className="page-head"><div><div className="eyebrow">Finding / {finding.detectorId ?? finding.source}</div><h1>{finding.title}</h1><p className="subhead">Recorded {formatDate(finding.createdAt)} · <Link className="muted-link" href={`/hunts/${finding.scanId}`}>{scan?.repositoryName ?? "View hunt"}</Link></p></div><SeverityBadge value={finding.severity} /></header>
    <section className="card"><dl className="details"><div className="detail"><dt>Confidence</dt><dd>{finding.confidence}%</dd></div><div className="detail"><dt>Source</dt><dd className="mono">{finding.source}</dd></div><div className="detail"><dt>Contract / Function</dt><dd className="mono">{finding.contract ?? "—"} / {finding.functionName ?? "—"}</dd></div><div className="detail"><dt>Verification</dt><dd><FindingStatusBadge value={finding.status} /></dd></div><div className="detail" style={{ gridColumn: "1 / -1" }}><dt>Location</dt><dd className="mono">{finding.filePath ?? "—"}{finding.startLine ? `:${finding.startLine}${finding.endLine && finding.endLine !== finding.startLine ? `–${finding.endLine}` : ""}` : ""}</dd></div></dl></section>
    {[['Root cause', finding.rootCause], ['Attack scenario', finding.attackScenario], ['Impact', finding.impact], ['Evidence', finding.evidence]].filter(([, content]) => content).map(([title, content]) => <section className="article-section" key={title}><h2>{title}</h2><p>{content}</p></section>)}
  </article>;
}
