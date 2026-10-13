"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import type { AuditPriorityFactor, AuditPriorityResult } from "@contracthunter/core";
import { auditConcepts, auditFactorRules } from "@contracthunter/core/audit-priority-catalog";

type Mode = "beginner" | "researcher";
type Contract = AuditPriorityResult["rankedContracts"][number];
const viewNames: Record<Contract["securityViews"][number], string> = {
  "money-flow": "Money Flow", permissions: "Permissions", "oracle-flow": "Oracle Flow",
  "external-calls": "External Calls", upgradeability: "Upgradeability", "attack-surface": "Attack Surface", findings: "Findings",
};
const warningText: Record<AuditPriorityResult["warnings"][number]["code"], string> = {
  "repository-map-unavailable": "Repository classification unavailable",
  "graph-analysis-partial": "Static graph analysis partial",
  "contracts-without-source-omitted": "Contracts without exact source omitted from ranking",
  "functions-without-source-omitted": "Functions without exact source omitted from recommendations",
  "oracle-evidence-unavailable": "Oracle classification incomplete",
  "access-control-extraction-unavailable": "AccessControl extraction incomplete",
  "call-target-unresolved": "External call targets unresolved",
  "syntax-facts-unavailable": "Some function syntax facts unavailable",
  "security-view-truncated": "Security View output bounded",
  "output-truncated": "Recommendations bounded",
};
const sourceHref = (scanId: string, source: Contract["source"]) =>
  `/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(source.sourceUnitName)}&line=${source.startLine}`;
const contractHref = (scanId: string, contractId: string, mode: Mode) =>
  `/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(contractId)}?mode=${mode}`;
const functionHref = (scanId: string, contractId: string, functionId: string, mode: Mode) =>
  `/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(contractId)}/functions/${encodeURIComponent(functionId)}?mode=${mode}`;
const mapHref = (scanId: string, mode: Mode, contractId?: string, view?: string) =>
  `/hunts/${encodeURIComponent(scanId)}/protocol-map?mode=${mode}${view ? `&view=${view}` : ""}${contractId ? `&node=${encodeURIComponent(contractId)}` : ""}`;
export function conceptFor(key: string) { return Object.prototype.hasOwnProperty.call(auditConcepts, key) ?
  auditConcepts[key as keyof typeof auditConcepts] : null; }
function Concept({ conceptKey, mode }: { conceptKey: string; mode: Mode }) {
  const concept = conceptFor(conceptKey);
  return <details className="sh-concept"><summary>{concept?.term ?? "Explanation unavailable"}</summary>
    {concept ? <div><p><strong>What this means:</strong> {concept.meaning}</p><p><strong>Why this matters:</strong> {concept.why}</p>
      <p><strong>What to inspect:</strong> {concept.inspect.join(" ")}</p></div> :
      <p>Concept explanation unavailable. Inspect the cited evidence directly.</p>}
    {mode === "researcher" && <small className="mono">Concept key: {concept ? conceptKey : "unknown"}</small>}</details>;
}
function Evidence({ factor, scanId, mode }: { factor: AuditPriorityFactor; scanId: string; mode: Mode }) {
  return <details className="sh-evidence"><summary>Show evidence ({factor.evidence.length})</summary><ul>
    {factor.evidence.map((item) => <li key={`${item.kind}:${item.id}`}><span>{item.kind}</span>
      {item.source ? <Link href={sourceHref(scanId, item.source)}>{item.source.sourceUnitName}:{item.source.startLine} ↗</Link> :
        <span>Exact source unavailable</span>}
      {item.kind === "finding-link" && <Link href={`/findings/${encodeURIComponent(item.id.split(":pn:")[0])}`}>Open finding ↗</Link>}
      {mode === "researcher" && <code>{item.id}</code>}</li>)}</ul></details>;
}
function Factors({ factors, scanId, mode }: { factors: readonly AuditPriorityFactor[]; scanId: string; mode: Mode }) {
  return <ul className="sh-factors">{factors.map((factor) => { const concept = conceptFor(factor.explanationKey);
    return <li key={factor.id}><div><strong>{concept?.term ?? "Unknown review factor"}</strong>
      <span className="muted"> · {factor.count} exact {factor.count === 1 ? "fact" : "facts"}</span>
      {mode === "researcher" && <span className="mono"> · {factor.id} +{factor.points} / {factor.potentialPoints}</span>}</div>
      <Concept conceptKey={factor.explanationKey} mode={mode} /><Evidence factor={factor} scanId={scanId} mode={mode} /></li>; })}</ul>;
}
function ContractCard({ item, rank, scanId, mode }: { item: Contract; rank: number; scanId: string; mode: Mode }) {
  return <li className="card sh-card"><div className="sh-card-head"><div><span className="eyebrow">#{rank} · {item.classification}</span>
      <h3>{item.name}</h3><Link className="muted-link mono" href={sourceHref(scanId, item.source)}>{item.source.sourceUnitName}:{item.source.startLine} ↗</Link></div>
      <div className="sh-score"><strong>{item.score} / 100</strong><span>Audit Priority</span></div></div>
    <div className="sh-actions"><Link href={contractHref(scanId, item.id, mode)}>Open Contract</Link>
      <Link href={mapHref(scanId, mode, item.id)}>Show on Protocol Map</Link>
      {item.findingCount > 0 && <Link href={`${contractHref(scanId, item.id, mode)}#findings`}>{item.findingCount} findings</Link>}</div>
    {mode === "beginner" ? <details className="sh-why" open={rank === 1}><summary>Why start here?</summary>
      <Factors factors={item.factors} scanId={scanId} mode={mode} /></details> :
      <section className="sh-why"><h4>Factor contributions</h4><Factors factors={item.factors} scanId={scanId} mode={mode} />
        <p className="mono">Contract ID: {item.id} · uncapped: {item.uncappedScore}</p></section>}
    <section><h4>Start with these functions</h4>{item.recommendedFunctions.length ? <ol className="sh-functions">
      {item.recommendedFunctions.map((fn) => <li key={fn.id}><div><strong className="mono">{fn.signature}</strong>
        {mode === "researcher" && <span className="mono"> · Review Priority {fn.score} / 100</span>}</div>
        <div className="sh-actions"><Link href={functionHref(scanId, item.id, fn.id, mode)}>Open Function</Link>
          <Link href={sourceHref(scanId, fn.source)}>Source ↗</Link></div>
        <details><summary>Why inspect it?</summary><Factors factors={fn.factors} scanId={scanId} mode={mode} /></details></li>)}</ol> :
      <p className="muted">No source-linked function recommendation was available.</p>}</section>
    {!!item.securityViews.length && <section><h4>Relevant Security Views</h4><div className="sh-actions">
      {item.securityViews.map((view) => <Link key={view} href={mapHref(scanId, mode, item.id, view)}>{viewNames[view]}</Link>)}</div></section>}
    {!!item.checklist.length && <details><summary>Review checklist ({item.checklist.length})</summary><ul className="sh-checklist">
      {item.checklist.map((check, i) => <li key={`${check.conceptKey}:${i}`}>{check.prompt}
        {check.findingIds.map((id) => <Link key={id} href={`/findings/${encodeURIComponent(id)}`}>Open finding ↗</Link>)}</li>)}</ul>
      <p className="muted">These are investigation prompts, not saved audit progress or defect claims.</p></details>}
    {mode === "researcher" && <p className="mono sh-identity">Qualified identity: {item.qualifiedName}</p>}
  </li>;
}
export function StartHere({ result, repositoryName, initialMode = "beginner" }: {
  result: AuditPriorityResult; repositoryName: string; initialMode?: Mode;
}) {
  const [mode, setMode] = useState<Mode>(initialMode), [query, setQuery] = useState(""),
    [filter, setFilter] = useState("all"), [showMore, setShowMore] = useState(false);
  const scanId = result.scanId, overview = result.projectOverview;
  const ranked = useMemo(() => result.rankedContracts.filter((item) => {
    const text = `${item.name} ${item.qualifiedName} ${item.source.sourceUnitName} ${item.recommendedFunctions.map((fn) => fn.signature).join(" ")}`.toLocaleLowerCase();
    return text.includes(query.trim().toLocaleLowerCase()) && (filter === "all" || filter === "core" && item.classification === "core" ||
      filter === "findings" && item.findingCount > 0 || item.securityViews.includes(filter as Contract["securityViews"][number]));
  }), [result.rankedContracts, query, filter]);
  const visible = query || filter !== "all" || showMore ? ranked : ranked.slice(0, 5);
  function changeMode(next: Mode) { setMode(next); const url = new URL(window.location.href); url.searchParams.set("mode", next);
    window.history.replaceState(null, "", url.toString()); }
  const stats = [
    ["Solidity files", overview.solidityFiles ?? "Unavailable"], ["Contracts", overview.contracts], ["Core protocol", overview.coreContracts],
    ["Periphery", overview.peripheryContracts], ["Interfaces", overview.interfaces], ["Libraries", overview.libraries],
    ["External entry points", overview.externalEntryPoints], ["External calls", overview.externalCalls],
    ["Unresolved calls", overview.unresolvedCalls], ["Token-transfer-like operations", overview.tokenTransferLikeOperations],
    ["Native value transfers", overview.nativeValueTransfers], ["Proxy relationships", overview.proxyRelationships],
    ["Control relationships", overview.controlRelationships], ["Contracts with findings", overview.contractsWithFindings],
  ] as const;
  return <main className="sh-page"><nav aria-label="Breadcrumb" className="ce-breadcrumb"><Link href={`/hunts/${encodeURIComponent(scanId)}`}>{repositoryName}</Link>
    <span>/</span><Link href={mapHref(scanId, mode)}>Protocol Map</Link><span>/</span><strong>Start Here</strong></nav>
    <header className="page-head"><div><div className="eyebrow">Protocol Intelligence / Research guide</div><h1>Show Me Where To Start</h1>
      <p className="subhead">A source-linked starting point for manual review of {repositoryName}.</p></div>
      <div className="sh-actions"><Link className="button secondary-button" href={mapHref(scanId, mode)}>Protocol Map →</Link></div></header>
    <div className="sh-mode" role="group" aria-label="Display mode"><button type="button" aria-pressed={mode === "beginner"} onClick={() => changeMode("beginner")}>Beginner</button>
      <button type="button" aria-pressed={mode === "researcher"} onClick={() => changeMode("researcher")}>Researcher</button></div>
    {result.analysisStatus === "partial" && <section className="sh-warning" role="status"><strong>Partial analysis</strong>
      <p>This ranking uses the evidence ContractHunter could determine. Unknown or unresolved facts are not treated as safety evidence.</p>
      <ul>{result.warnings.map((item) => <li key={item.code}>{warningText[item.code]}: {item.count}</li>)}</ul></section>}
    <section className="section"><div className="section-head"><h2>Project Overview</h2></div><dl className="sh-stats">{stats.map(([label, value]) =>
      <div className="card" key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      {overview.filesByClass.length > 0 && <details><summary>Repository file classifications</summary><dl className="sh-classifications">
        {overview.filesByClass.map((item) => <div key={item.classification}><dt>{item.classification}</dt><dd>{item.count}</dd></div>)}</dl></details>}</section>
    <section className="section"><h2>Show Me Where To Start</h2><p className="sh-disclaimer">{result.scoreMeaning}</p>
      <p className="muted">Recommendations use static repository analysis and existing ContractHunter findings. Runtime behavior may differ.</p>
      {result.rankedContracts[0] && <p className="sh-first"><Link className="button" href={contractHref(scanId, result.rankedContracts[0].id, mode)}>
        Start with {result.rankedContracts[0].name} →</Link></p>}
      <details className="sh-method"><summary>How ranking works</summary><p>ContractHunter orders source-linked contracts by a fixed, versioned set of review factors. Counts use capped buckets; finding count cannot grow the score without limit. The browser cannot change weights.</p>
        {mode === "researcher" && <><p className="mono">Ruleset: {result.rulesetVersion} · Model: {result.schema} · Graph: {result.protocolGraphId}</p>
          <dl className="sh-classifications">{Object.entries(auditFactorRules).map(([id, rule]) => <div key={id}><dt>{id}</dt><dd>maximum +{rule.max}</dd></div>)}</dl></>}</details>
      <div className="sh-tools"><label>Search recommendations <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Contract, source path, function" /></label>
        <label>Filter <select value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All recommendations</option><option value="core">Core only</option>
          <option value="findings">With findings</option><option value="money-flow">Money Flow</option><option value="permissions">Permissions</option>
          <option value="upgradeability">Upgradeability</option><option value="external-calls">External Calls</option></select></label></div>
      <p className="muted">Showing {visible.length} of {result.totalRankableContracts} source-linked rankable contracts. Other and unclassified contracts remain in the Protocol Map.</p>
      {visible.length ? <ol className="sh-ranks">{visible.map((item) => <ContractCard key={item.id} item={item}
        rank={result.rankedContracts.indexOf(item) + 1} scanId={scanId} mode={mode} />)}</ol> :
        <p className="card">{result.rankedContracts.length ? "No recommendations match this presentation filter." :
          "ContractHunter could not derive enough source-linked structure to rank contracts for this scan. Review the Protocol Map and analysis warnings."}</p>}
      {!query && filter === "all" && !showMore && ranked.length > 5 && <button type="button" className="button secondary-button" onClick={() => setShowMore(true)}>Show more recommendations</button>}
      <p><Link className="muted-link" href={mapHref(scanId, mode)}>Show all contracts in Protocol Map →</Link></p></section>
    {result.rankedContracts[0] && <section className="section card"><h2>A practical first pass</h2><ol className="sh-workflow">
      <li>Open {result.rankedContracts[0].name} in Contract Explorer.</li><li>Inspect its recommended functions and external entry points.</li>
      {result.rankedContracts[0].securityViews.map((view) => <li key={view}><Link href={mapHref(scanId, mode, result.rankedContracts[0].id, view)}>Review {viewNames[view]}</Link>.</li>)}
      {result.rankedContracts[0].findingCount > 0 && <li>Review attached ContractHunter findings in their current lifecycle state.</li>}
      <li>Use Impact Lab only from an existing eligible finding or hypothesis workflow.</li></ol></section>}
    {mode === "researcher" && <section className="section"><h2>Derivation identity</h2><p className="mono sh-identity">{result.derivationVersion} · {result.contentSha256}</p>
      <p className="mono sh-identity">Catalog: {result.explanationCatalogVersion} · Repository Map: {result.repositoryMapId}</p></section>}
  </main>;
}
