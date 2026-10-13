import Link from "next/link";
import { notFound } from "next/navigation";
import { getDatabase, getFinding, getScan, readStaticProtocolGraph } from "@contracthunter/db";
import { FindingStatusBadge, SeverityBadge } from "@/components/badges";
import { formatDate } from "@/components/format";

export const dynamic = "force-dynamic";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const database = getDatabase();
  const finding = getFinding(database, (await params).id);
  if (!finding) notFound();
  const scan = getScan(database, finding.scanId);
  let graphTargets: Array<{ id: string; kind: string; name: string; ownerId: string;
    source: { sourceUnitName: string; startLine: number } | null }> = [];
  let additionalTargets = 0;
  try {
    const artifact = readStaticProtocolGraph(database, finding.scanId);
    if (artifact) {
      const nodes = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
      const linked = artifact.findingLinks.filter((link) => link.findingId === finding.id);
      additionalTargets = Math.max(0, linked.length - 32);
      graphTargets = linked.slice(0, 32).flatMap((link) => {
        const node = nodes.get(link.nodeId);
        return node ? [{ id: node.id, kind: node.kind, name: node.name, source: node.source,
          ownerId: node.kind === "function" ? node.contractId : node.id }] : [];
      });
    }
  } catch { graphTargets = []; additionalTargets = 0; }
  return <article className="article">
    <header className="page-head"><div><div className="eyebrow">Finding / {finding.detectorId ?? finding.source}</div><h1>{finding.title}</h1><p className="subhead">Recorded {formatDate(finding.createdAt)} · <Link className="muted-link" href={`/hunts/${finding.scanId}`}>{scan?.repositoryName ?? "View hunt"}</Link></p></div><SeverityBadge value={finding.severity} /></header>
    <section className="card"><dl className="details"><div className="detail"><dt>Confidence</dt><dd>{finding.confidence}%</dd></div><div className="detail"><dt>Source</dt><dd className="mono">{finding.source}</dd></div><div className="detail"><dt>Contract / Function</dt><dd className="mono">{finding.contract ?? "—"} / {finding.functionName ?? "—"}</dd></div><div className="detail"><dt>Verification</dt><dd><FindingStatusBadge value={finding.status} /></dd></div><div className="detail" style={{ gridColumn: "1 / -1" }}><dt>Location</dt><dd className="mono">{finding.filePath ?? "—"}{finding.startLine ? `:${finding.startLine}${finding.endLine && finding.endLine !== finding.startLine ? `–${finding.endLine}` : ""}` : ""}</dd></div></dl></section>
    {graphTargets.length > 0 && <section className="article-section"><h2>Protocol context</h2><p>Exact static graph attachment. This does not establish runtime reachability or exploitability.</p>
      <ul className="reason-list">{graphTargets.map((target) => <li key={target.id}>{target.kind}: {target.name} ·
        <Link className="muted-link" href={`/hunts/${encodeURIComponent(finding.scanId)}/protocol-map?node=${encodeURIComponent(target.ownerId)}`}> Show in Protocol Map →</Link>
        {target.kind === "function" ? <Link className="muted-link" href={`/hunts/${encodeURIComponent(finding.scanId)}/contracts/${encodeURIComponent(target.ownerId)}/functions/${encodeURIComponent(target.id)}`}> Open Function →</Link> :
          <Link className="muted-link" href={`/hunts/${encodeURIComponent(finding.scanId)}/contracts/${encodeURIComponent(target.id)}`}> Open Contract →</Link>}
        {target.source && <Link className="muted-link" href={`/hunts/${encodeURIComponent(finding.scanId)}/source?unit=${encodeURIComponent(target.source.sourceUnitName)}&line=${target.source.startLine}`}> View Source →</Link>}</li>)}</ul>
      {additionalTargets > 0 && <p className="muted">{additionalTargets} additional exact graph attachments omitted from this bounded detail view.</p>}</section>}
    {[['Root cause', finding.rootCause], ['Attack scenario', finding.attackScenario], ['Impact', finding.impact], ['Evidence', finding.evidence]].filter(([, content]) => content).map(([title, content]) => <section className="article-section" key={title}><h2>{title}</h2><p>{content}</p></section>)}
  </article>;
}
