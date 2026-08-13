import { notFound } from "next/navigation";
import Link from "next/link";
import { getDatabase, getScan, listFindings } from "@contracthunter/db";
import { ScanBadge, SeverityBadge, FindingStatusBadge } from "@/components/badges";
import { formatDate } from "@/components/format";
import { ScanPoller } from "@/components/scan-poller";

export const dynamic = "force-dynamic";

const progress = { queued: 8, cloning: 28, detecting: 52, scanning: 76, completed: 100, failed: 100 } as const;
const parseList = (value: string | null): string[] => { try { return value ? JSON.parse(value) as string[] : []; } catch { return []; } };

export default async function HuntPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const database = getDatabase();
  const scan = getScan(database, id);
  if (!scan) notFound();
  const found = listFindings(database, { scanId: scan.id });
  const active = !["completed", "failed"].includes(scan.status);
  const compilerConstraints = parseList(scan.compilerConstraints);
  const compilerVersions = parseList(scan.compilerVersions);
  return <>
    <ScanPoller active={active} />
    <header className="page-head"><div><div className="eyebrow">Hunt / {scan.id.slice(0, 8)}</div><h1>{scan.repositoryName}</h1><p className="subhead mono">{scan.repositoryUrl}</p></div><ScanBadge value={scan.status} /></header>
    {scan.error && <div className="error"><strong>Hunt failed:</strong> {scan.error}</div>}
    <section className="card">
      <dl className="details">
        <div className="detail"><dt>Exact commit</dt><dd className="mono">{scan.resolvedCommit ?? "Resolving…"}</dd></div>
        <div className="detail"><dt>Framework</dt><dd>{scan.framework}</dd></div>
        <div className="detail"><dt>Requested ref</dt><dd className="mono">{scan.requestedRef ?? "Default branch"}</dd></div>
        <div className="detail"><dt>Depth</dt><dd>{scan.depth}</dd></div>
        <div className="detail"><dt>Queued</dt><dd>{formatDate(scan.createdAt)}</dd></div>
        <div className="detail"><dt>Started</dt><dd>{formatDate(scan.startedAt)}</dd></div>
        <div className="detail"><dt>Completed</dt><dd>{formatDate(scan.completedAt)}</dd></div>
        <div className="detail"><dt>Findings</dt><dd>{found.length}</dd></div>
      </dl>
      <div className="progress-track"><div className="progress-bar" style={{ width: `${progress[scan.status]}%`, background: scan.status === "failed" ? "#ff6767" : undefined }} /></div>
    </section>
    <section className="section"><div className="section-head"><h2>Solidity Compiler</h2></div><div className="card"><dl className="details"><div className="detail"><dt>Detected</dt><dd className="mono">{compilerConstraints.length ? compilerConstraints.join(", ") : "—"}</dd></div><div className="detail"><dt>Resolved</dt><dd className="mono">{compilerVersions.length ? compilerVersions.join(", ") : "—"}</dd></div><div className="detail"><dt>Source</dt><dd>{scan.compilerDetectionSource === "foundry-config" ? "Foundry config" : scan.compilerDetectionSource === "pragma" ? "Solidity pragma" : "—"}</dd></div><div className="detail"><dt>Status</dt><dd><span className={`badge ${scan.compilerStatus === "ready" || scan.compilerStatus === "cached" ? "green" : scan.compilerStatus === "failed" ? "red" : scan.compilerStatus === "downloading" ? "purple" : "gray"}`}>{scan.compilerStatus}</span></dd></div></dl>{scan.compilerError && <div className="error" style={{ marginTop: 18, marginBottom: 0 }}>{scan.compilerError}</div>}</div></section>
    <section className="section"><div className="section-head"><h2>Scanner</h2></div><div className="card"><dl className="details"><div className="detail"><dt>Name</dt><dd>{scan.scannerName ?? "Slither"}</dd></div><div className="detail"><dt>Status</dt><dd><span className={`badge ${scan.scannerStatus === "completed" || scan.scannerStatus === "available" ? "green" : scan.scannerStatus === "failed" ? "red" : scan.scannerStatus === "running" ? "purple" : "gray"}`}>{scan.scannerStatus}</span></dd></div><div className="detail"><dt>Findings</dt><dd>{found.length}</dd></div><div className="detail"><dt>Duration</dt><dd>{scan.scannerDurationMs === null ? "—" : `${(scan.scannerDurationMs / 1000).toFixed(2)}s`}</dd></div></dl></div></section>
    <section className="section"><div className="section-head"><h2>Findings</h2><span className="muted mono" style={{ fontSize: 11 }}>{found.length} RESULTS</span></div><div className="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Contract</th><th>Source</th><th>Confidence</th><th>Status</th></tr></thead><tbody>{found.map((finding) => <tr key={finding.id}><td><SeverityBadge value={finding.severity} /></td><td className="finding-title"><Link className="repo" href={`/findings/${finding.id}`}>{finding.title}</Link></td><td className="mono">{finding.contract ?? "—"}</td><td>{finding.source}</td><td>{finding.confidence}%</td><td><FindingStatusBadge value={finding.status} /></td></tr>)}{found.length === 0 && <tr><td colSpan={6} className="empty">{active ? "The scan pipeline is running…" : "No findings were produced."}</td></tr>}</tbody></table></div></section>
  </>;
}
