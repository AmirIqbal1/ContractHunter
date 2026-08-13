import { notFound } from "next/navigation";
import Link from "next/link";
import { loadConfig } from "@contracthunter/core";
import { getCurrentProtocolAnalysis, getDatabase, getScan, listFindings, listInvestigations, listInvariants, listProtocolAnalyses, listScanScanners } from "@contracthunter/db";
import { ScanBadge, SeverityBadge, FindingStatusBadge } from "@/components/badges";
import { formatDate } from "@/components/format";
import { ScanPoller } from "@/components/scan-poller";
import { AIAnalysisControl } from "@/components/ai-analysis-control";

export const dynamic = "force-dynamic";

const progress = { queued: 6, cloning: 20, detecting: 34, preparing_dependencies: 50, preparing_compiler: 66, scanning: 82, completed: 100, failed: 100 } as const;
const parseList = (value: string | null): string[] => { try { return value ? JSON.parse(value) as string[] : []; } catch { return []; } };
type DependencyMetadata = { gitSubmodulesDetected?: number; gitSubmodulesPrepared?: number; npmDependenciesDetected?: number; npmDependenciesPrepared?: number; lockfile?: string | null; durationMs?: number; warnings?: string[] };
const parseDependencyMetadata = (value: string | null): DependencyMetadata => { try { return value ? JSON.parse(value) as DependencyMetadata : {}; } catch { return {}; } };

export default async function HuntPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const database = getDatabase();
  const scan = getScan(database, id);
  if (!scan) notFound();
  const found = listFindings(database, { scanId: scan.id });
  const investigations = listInvestigations(database, { scanId: scan.id });
  const scanners = listScanScanners(database, scan.id);
  const active = !["completed", "failed"].includes(scan.status);
  const compilerConstraints = parseList(scan.compilerConstraints);
  const compilerVersions = parseList(scan.compilerVersions);
  const dependencies = parseDependencyMetadata(scan.dependencyMetadata);
  const correlated = investigations.filter((item) => item.sourceCount > 1).length;
  const ai = getCurrentProtocolAnalysis(database, scan.id);
  const invariantCount = listInvariants(database, { scanId: scan.id }).length;
  const analysisHistory = listProtocolAnalyses(database, scan.id).length;
  const aiConfig = loadConfig();
  const manifest = ai ? parseDependencyMetadata(ai.contextManifest) as { approximateInputBytes?: number } : {};
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
        <div className="detail"><dt>Investigations / raw findings</dt><dd>{investigations.length} / {found.length}</dd></div>
      </dl>
      <div className="progress-track"><div className="progress-bar" style={{ width: `${progress[scan.status]}%`, background: scan.status === "failed" ? "#ff6767" : undefined }} /></div>
    </section>
    <section className="section"><div className="section-head"><h2>Dependencies</h2></div><div className="card"><dl className="details"><div className="detail"><dt>Git submodules</dt><dd>{dependencies.gitSubmodulesDetected ? `${dependencies.gitSubmodulesPrepared ?? 0} of ${dependencies.gitSubmodulesDetected} prepared` : "Not required"}</dd></div><div className="detail"><dt>npm</dt><dd>{dependencies.lockfile ? `${dependencies.npmDependenciesPrepared ?? 0} packages prepared from ${dependencies.lockfile}` : dependencies.warnings?.some((warning) => warning.includes("lockfile")) ? "Skipped — no lockfile" : "Not required"}</dd></div><div className="detail"><dt>Status</dt><dd><span className={`badge ${scan.dependencyStatus === "ready" ? "green" : scan.dependencyStatus === "failed" ? "red" : scan.dependencyStatus === "preparing" ? "purple" : "gray"}`}>{scan.dependencyStatus}</span></dd></div><div className="detail"><dt>Duration</dt><dd>{dependencies.durationMs === undefined ? "—" : `${(dependencies.durationMs / 1000).toFixed(2)}s`}</dd></div></dl>{dependencies.warnings?.map((warning) => <div className="muted" style={{ marginTop: 14 }} key={warning}>{warning}</div>)}{scan.dependencyError && <div className="error" style={{ marginTop: 18, marginBottom: 0 }}>{scan.dependencyError}</div>}</div></section>
    <section className="section"><div className="section-head"><h2>Solidity Compiler</h2></div><div className="card"><dl className="details"><div className="detail"><dt>Detected</dt><dd className="mono">{compilerConstraints.length ? compilerConstraints.join(", ") : "—"}</dd></div><div className="detail"><dt>Resolved</dt><dd className="mono">{compilerVersions.length ? compilerVersions.join(", ") : "—"}</dd></div><div className="detail"><dt>Source</dt><dd>{scan.compilerDetectionSource === "foundry-config" ? "Foundry config" : scan.compilerDetectionSource === "pragma" ? "Solidity pragma" : "—"}</dd></div><div className="detail"><dt>Status</dt><dd><span className={`badge ${scan.compilerStatus === "ready" || scan.compilerStatus === "cached" ? "green" : scan.compilerStatus === "failed" ? "red" : scan.compilerStatus === "downloading" ? "purple" : "gray"}`}>{scan.compilerStatus}</span></dd></div></dl>{scan.compilerError && <div className="error" style={{ marginTop: 18, marginBottom: 0 }}>{scan.compilerError}</div>}</div></section>
    <section className="section"><div className="section-head"><h2>Security scanners</h2></div><div className="card"><dl className="details">{scanners.length ? scanners.map((scanner) => <div className="detail" key={scanner.scannerId}><dt>{scanner.scannerName}</dt><dd><span className={`badge ${scanner.status === "completed" ? "green" : scanner.status === "failed" || scanner.status === "unavailable" ? "red" : scanner.status === "running" ? "purple" : "gray"}`}>{scanner.status}</span><div className="muted" style={{ marginTop: 7 }}>{scanner.findingCount} findings · {scanner.durationMs === null ? "—" : `${(scanner.durationMs / 1000).toFixed(2)}s`}</div>{scanner.error && <div className="muted" style={{ marginTop: 7 }}>{scanner.error}</div>}</dd></div>) : <div className="detail"><dt>Scanners</dt><dd><span className="badge gray">pending</span></dd></div>}</dl></div></section>
    <section className="section"><div className="section-head"><h2>AI Protocol Analysis</h2>{ai && <Link className="muted-link" href={`/protocol-analyses/${ai.id}`}>View protocol model →</Link>}</div><div className="card"><dl className="details"><div className="detail"><dt>Status</dt><dd><span className={`badge ${scan.aiStatus === "completed" ? (ai?.coverageStatus === "partial" ? "amber" : "green") : scan.aiStatus === "failed" ? "red" : scan.aiStatus === "running" || scan.aiStatus === "pending" ? "purple" : "gray"}`}>{ai?.coverageStatus === "partial" ? "partial coverage" : scan.aiStatus === "pending" ? "ready" : scan.aiStatus}</span></dd></div><div className="detail"><dt>Provider / model</dt><dd>{ai ? `${ai.provider} / ${ai.actualModel ?? ai.requestedModel}` : aiConfig.AI_ENABLED ? `OpenAI / ${aiConfig.OPENAI_MODEL}` : "—"}</dd></div><div className="detail"><dt>Protocol type</dt><dd>{ai ? parseList(ai.protocolTypes).join(", ") : "—"}</dd></div><div className="detail"><dt>Invariants / versions</dt><dd>{invariantCount} / {analysisHistory}</dd></div><div className="detail"><dt>Duration</dt><dd>{ai ? `${(ai.durationMs / 1000).toFixed(1)}s` : "—"}</dd></div><div className="detail"><dt>Token usage</dt><dd>{ai?.totalTokens ?? "—"}</dd></div><div className="detail"><dt>Submitted context</dt><dd>{manifest.approximateInputBytes ? `~${Math.ceil(manifest.approximateInputBytes / 1024)} KiB` : "Calculated before request"}</dd></div><div className="detail"><dt>Meaning</dt><dd>Architectural evidence, not vulnerability probability</dd></div></dl>{scan.aiError && <div className="error" style={{ marginTop: 18 }}>{scan.aiError}</div>}<AIAnalysisControl scanId={scan.id} enabled={aiConfig.AI_ENABLED} configured={Boolean(aiConfig.OPENAI_API_KEY)} label={ai ? "RERUN AI ANALYSIS" : "RUN AI ANALYSIS"} /></div></section>
    <section className="section"><div className="section-head"><h2>Investigation summary</h2></div><div className="stats"><div className="card"><div className="stat-label">Raw findings</div><div className="stat-number">{found.length}</div></div><div className="card"><div className="stat-label">Investigations</div><div className="stat-number">{investigations.length}</div></div><div className="card"><div className="stat-label">Multi-scanner</div><div className="stat-number">{correlated}</div></div><div className="card"><div className="stat-label">Single-source</div><div className="stat-number">{investigations.length - correlated}</div></div></div><div className="severity-grid" style={{ marginTop: 12 }}>{(["critical", "high", "medium", "low"] as const).map((severity) => <div className="severity-cell" key={severity}><span className={`badge ${severity === "critical" || severity === "high" ? "red" : severity === "medium" ? "amber" : "blue"}`}>{severity}</span><strong>{investigations.filter((item) => item.severity === severity).length}</strong></div>)}</div></section>
    <section className="section"><div className="section-head"><h2>Prioritised investigations</h2><Link className="muted-link" href={`/investigations?scan=${scan.id}`}>View all →</Link></div><div className="table-wrap"><table><thead><tr><th>Priority</th><th>Severity</th><th>Candidate</th><th>Confidence</th><th>Sources</th></tr></thead><tbody>{investigations.slice(0, 5).map((item) => <tr key={item.id}><td className="mono"><strong>{item.priorityScore}</strong></td><td><SeverityBadge value={item.severity} /></td><td className="finding-title"><Link className="repo" href={`/investigations/${item.id}`}>{item.title}</Link></td><td>{item.confidenceScore}%</td><td>{item.sourceCount}</td></tr>)}{investigations.length === 0 && <tr><td colSpan={5} className="empty">{active ? "Correlation runs after scanner results arrive…" : "No investigation candidates were produced."}</td></tr>}</tbody></table></div></section>
    <section className="section"><div className="section-head"><h2>Findings</h2><span className="muted mono" style={{ fontSize: 11 }}>{found.length} RESULTS</span></div><div className="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Contract</th><th>Source</th><th>Confidence</th><th>Status</th></tr></thead><tbody>{found.map((finding) => <tr key={finding.id}><td><SeverityBadge value={finding.severity} /></td><td className="finding-title"><Link className="repo" href={`/findings/${finding.id}`}>{finding.title}</Link></td><td className="mono">{finding.contract ?? "—"}</td><td><span className="badge gray">{finding.source}</span></td><td>{finding.confidence}%</td><td><FindingStatusBadge value={finding.status} /></td></tr>)}{found.length === 0 && <tr><td colSpan={6} className="empty">{active ? "The scan pipeline is running…" : "No findings were produced."}</td></tr>}</tbody></table></div></section>
  </>;
}
