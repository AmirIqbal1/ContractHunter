import Link from "next/link";
import { dashboardStats, getDatabase, listScans } from "@contracthunter/db";
import { severities } from "@contracthunter/core";
import { ScanBadge } from "@/components/badges";
import { formatDate, shortSha } from "@/components/format";

export const dynamic = "force-dynamic";

export default function Dashboard() {
  const database = getDatabase();
  const stats = dashboardStats(database);
  const recent = listScans(database, 8);
  return <>
    <header className="page-head"><div><div className="eyebrow">Security workstation / Overview</div><h1>Hunt dashboard</h1><p className="subhead">Authorised Solidity repository analysis, running entirely on your machine.</p></div><Link className="button" href="/hunts/new">+ NEW HUNT</Link></header>
    <section className="stats">
      <div className="card"><div className="stat-label">Total hunts</div><div className="stat-number">{stats.totalScans}</div></div>
      <div className="card"><div className="stat-label">Completed</div><div className="stat-number">{stats.completedScans}</div></div>
      <div className="card"><div className="stat-label">Failed</div><div className="stat-number">{stats.failedScans}</div></div>
      <div className="card"><div className="stat-label">Total findings</div><div className="stat-number">{stats.totalFindings}</div></div>
    </section>
    <section className="section"><div className="section-head"><h2>Severity signal</h2></div><div className="severity-grid">{severities.map((severity) => <div className="severity-cell" key={severity}><span className={`badge ${severity === "critical" || severity === "high" ? "red" : severity === "medium" ? "amber" : severity === "low" ? "blue" : "gray"}`}>{severity}</span><strong>{stats.bySeverity[severity] ?? 0}</strong></div>)}</div></section>
    <section className="section"><div className="section-head"><h2>Recent hunts</h2><Link className="muted-link" href="/findings">Browse findings →</Link></div><div className="table-wrap"><table><thead><tr><th>Repository</th><th>Status</th><th>Framework</th><th>Commit</th><th>Started</th></tr></thead><tbody>{recent.map((scan) => <tr key={scan.id}><td><Link className="repo" href={`/hunts/${scan.id}`}>{scan.repositoryName}</Link><div className="muted mono" style={{ fontSize: 10, marginTop: 4 }}>{scan.depth.toUpperCase()}</div></td><td><ScanBadge value={scan.status} /></td><td>{scan.framework}</td><td className="mono">{shortSha(scan.resolvedCommit)}</td><td className="muted">{formatDate(scan.createdAt)}</td></tr>)}{recent.length === 0 && <tr><td colSpan={5} className="empty">No hunts yet. Start with an authorised GitHub repository.</td></tr>}</tbody></table></div></section>
  </>;
}
