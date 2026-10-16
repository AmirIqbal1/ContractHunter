import Link from "next/link";
import { notFound } from "next/navigation";
import { TextDecoder } from "node:util";
import type { ProtocolGraphNode, ProtocolSourceLocation } from "@contracthunter/core";
import { getDatabase, getScan, getScanSource, listFindings } from "@contracthunter/db";
import { ContractFunctions } from "@/components/contract-functions";
import { contractExplorerView, type ContractExplorerView, type ExplorerRelation } from "@/lib/contract-explorer";
import { loadProtocolMapForPage } from "@/lib/protocol-map-server";

export const dynamic = "force-dynamic";
const contractIdPattern = /^pn:[a-f0-9]{64}$/;
function sourceUrl(scanId: string, source: ProtocolSourceLocation) {
  return `/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(source.sourceUnitName)}&line=${source.startLine}`;
}
function Source({ scanId, source }: { scanId: string; source: ProtocolSourceLocation | null }) {
  return source ? <Link className="muted-link mono" href={sourceUrl(scanId, source)}>{source.sourceUnitName}:{source.startLine}{source.endLine !== source.startLine ? `–${source.endLine}` : ""} ↗</Link> :
    <span className="muted">Source location unavailable</span>;
}
function Entity({ scanId, node }: { scanId: string; node: ProtocolGraphNode }) {
  return node.kind === "contract" || node.kind === "interface" || node.kind === "library" ?
    <Link className="muted-link" href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(node.id)}`}>{node.name}</Link> :
    <span>{node.name}</span>;
}
function Relations({ title, rows, scanId, empty }: { title: string; rows: ExplorerRelation[]; scanId: string; empty: string }) {
  return <section className="section"><div className="section-head"><h2>{title}</h2><span className="muted">{rows.length}</span></div>
    {rows.length ? <ul className="ce-list">{rows.slice(0, 80).map(({ edge, from, to, fromFunction, toFunction }) => <li key={edge.id}>
      <div><strong><Entity scanId={scanId} node={from} /> → <Entity scanId={scanId} node={to} /></strong>
        <div className="ce-meta">{edge.kind}{fromFunction || toFunction ? ` · ${fromFunction?.signature ?? from.name} → ${toFunction?.signature ?? to.name}` : ""}</div>
        <div className="ce-meta">{edge.reasons.join(", ")} · {edge.evidence.map((item) => `${item.origin} ${item.producerVersion}`).join(", ")}</div></div>
      <Source scanId={scanId} source={edge.source} />
    </li>)}</ul> : <p className="card muted">{empty}</p>}
    {rows.length > 80 && <p className="ce-note">First 80 relationships shown. Use Protocol Map filters for the remaining relationships.</p>}
  </section>;
}
function Explorer({ view, repositoryName, preview, mode }: { view: ContractExplorerView; repositoryName: string;
  preview: Array<{ line: number; text: string }> | null; mode: "beginner" | "researcher" }) {
  const { contract, scanId, counts } = view;
  const mapHref = `/hunts/${encodeURIComponent(scanId)}/protocol-map`;
  const traits = [...new Set([...(contract.characteristics.map((item) => item.kind)),
    ...view.functions.flatMap((item) => item.node.characteristics.map((trait) => trait.kind))])].sort();
  const hasTokenLike = view.functions.some((item) => item.facts?.tokenTransferLike ||
    item.node.characteristics.some((trait) => trait.kind === "token-transfer"));
  const knownAssets = [...new Map([...view.incoming, ...view.outgoing].flatMap((item) => [item.from, item.to])
    .filter((node) => node.kind === "token").map((node) => [node.id, node])).values()];
  return <>
    <nav className="ce-breadcrumb" aria-label="Breadcrumb"><Link href={`/hunts/${scanId}`}>{repositoryName}</Link><span>/</span>
      <Link href={mapHref}>Protocol Map</Link><span>/</span><strong>{contract.name}</strong></nav>
    <header className="page-head"><div><div className="eyebrow">Contract Explorer / {contract.kind}</div>
      <h1>{contract.name}</h1><p className="subhead mono">{contract.qualifiedName}</p>
      <div className="ce-tags"><span>{contract.repositoryClassification.effective}</span><span>{contract.abstract ? "abstract contract" : contract.kind}</span>
        {contract.characteristics.some((item) => item.kind === "proxy") && <span>proven proxy</span>}
        {contract.characteristics.some((item) => item.kind === "implementation") && <span>implementation</span>}
        <span>{counts.findings} findings</span></div></div>
      <Link className="button secondary-button" href={`${mapHref}?mode=${mode}`}>← Back to Protocol Map</Link></header>
    <p className="ce-note">{mode === "beginner" ? "Start with external entry points, review cues, permissions and findings. Open a function for source-order details." :
      `Researcher context · canonical contract ID: ${contract.id} · classification: ${contract.repositoryClassification.effective}`}</p>
    <nav className="sh-mode" aria-label="Display mode"><Link aria-current={mode === "beginner" ? "page" : undefined}
      href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(contract.id)}?mode=beginner`}>Beginner</Link>
      <Link aria-current={mode === "researcher" ? "page" : undefined}
        href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(contract.id)}?mode=researcher`}>Researcher</Link></nav>
    {view.limited && <p className="pm-warning">This contract exceeds the bounded Explorer detail view. Counts describe the full graph; narrow review using the Protocol Map and source links.</p>}
    <div className="ce-actions"><Source scanId={scanId} source={contract.source} />
      <Link className="muted-link" href={`${mapHref}?node=${encodeURIComponent(contract.id)}`}>Show in Protocol Map →</Link></div>
    <section className="section"><h2>Purpose and overview</h2><div className="card"><p>Semantic purpose not yet classified. This {contract.repositoryClassification.effective} {contract.kind} exposes {counts.entryPoints} external entry points, has {counts.callees} outgoing contract relationships and {counts.callers} incoming contract relationships.</p>
      <div className="ce-metrics">{Object.entries(counts).map(([name, count]) => <div key={name}><span>{name}</span><strong>{count}</strong></div>)}</div></div></section>
    <section className="section"><h2>Security interest / Review cues</h2><div className="card">
      {view.cues.length ? <ul className="ce-cues">{view.cues.map((cue) => <li key={cue}>{cue}</li>)}</ul> : <p className="muted">No specific cues were extracted for this contract.</p>}
      <p className="ce-note">These structural indicators help direct review. They are not a vulnerability probability, severity, or proof of a bug.</p></div></section>
    <section className="section"><h2>Security characteristics and assets</h2><div className="card">
      <div className="ce-tags">{traits.length ? traits.map((trait) => <span key={trait}>{trait}</span>) : <span>No characteristics extracted</span>}</div>
      <p className="ce-note">{knownAssets.length ? `Known token graph identities: ${knownAssets.map((item) => item.name).join(", ")}.` :
        hasTokenLike ? "Token-transfer operations detected; exact asset identity unresolved." : "No asset identity is established by this graph."}</p>
      <p className="ce-note">Oracle dependencies appear only when source-backed graph evidence identifies them. Names alone are not classified as oracle evidence.</p></div></section>
    <ContractFunctions items={view.functions} scanId={scanId} mode={mode} />
    <section className="section" id="relationships"><h2>Relationships</h2><p className="muted">Calls out to {counts.callees} identities · called by {counts.callers} · libraries {counts.libraries} · inherited relationships {counts.inheritance} · unresolved {counts.unresolved}.</p></section>
    <Relations title="Called by" rows={view.incoming} scanId={scanId} empty="No incoming static relationships were resolved." />
    <Relations title="Calls and dependencies" rows={view.outgoing} scanId={scanId} empty="No outgoing static relationships were resolved." />
    <Relations title="Internal calls" rows={view.localCalls} scanId={scanId} empty="No internal call edge was extracted." />
    {view.unresolved.length > 0 && <section className="section"><h2>Unresolved external and structural calls</h2><p className="ce-note">ContractHunter detected a relationship but could not prove its target statically.</p>
      <ul className="ce-list">{view.unresolved.slice(0, 80).map((item, index) => <li key={`${item.callerFunctionId}-${index}`}>
        <div><strong className="mono">{item.caller.signature}</strong><div className="ce-meta">{item.kind} · target statically unresolved · {item.reason}{item.expression ? ` · ${item.expression}` : ""}</div></div>
        <Source scanId={scanId} source={item.source} /></li>)}</ul></section>}
    <Relations title="Inheritance" rows={view.inheritance} scanId={scanId} empty="No inheritance relationship extracted." />
    <Relations title="Interfaces" rows={view.interfaces} scanId={scanId} empty="No explicit interface relationship extracted." />
    <Relations title="Libraries used" rows={view.libraries} scanId={scanId} empty="No library-use edge extracted; imports alone do not count as use." />
    <Relations title="Proxy / implementation" rows={view.proxy} scanId={scanId} empty="No proven proxy or implementation relationship. Delegatecall alone is insufficient." />
    <Relations title="Permissions and control" rows={view.control} scanId={scanId} empty="No role or control relationship extracted. This does not establish permission safety." />
    <section className="section"><h2>Storage / state</h2>{view.state.length ? <ul className="ce-list">{view.state.slice(0, 100).map((item) => <li key={`${item.contractId}:${item.declarationId}`}>
      <div><strong className="mono">{item.variable}</strong><div className="ce-meta">Read by {item.readers.join(", ") || "none observed"}</div>
        <div className="ce-meta">Written by {item.writers.join(", ") || "none observed"}</div></div></li>)}</ul> :
      <p className="card muted">No variable-level state access extracted. Storage slots are not inferred.</p>}
      <p className="ce-note">Event emissions are not represented by the current static graph extractor.</p></section>
    <section className="section" id="findings"><div className="section-head"><h2>Findings</h2><span className="muted">{view.findings.length}</span></div>
      {view.findings.length ? <ul className="ce-list">{view.findings.slice(0, 100).map((finding) => <li key={finding.id}>
        <div><Link className="muted-link" href={`/findings/${finding.id}`}>{finding.title}</Link>
          <div className="ce-meta">{finding.detectorId ?? finding.source} · {finding.status}</div></div>
        {finding.filePath && <span className="mono ce-meta">{finding.filePath}{finding.startLine ? `:${finding.startLine}` : ""}</span>}</li>)}</ul> :
        <p className="card muted">No exact finding reference is attached to this contract or its functions.</p>}</section>
    <section className="section"><h2>Source and provenance</h2><div className="card"><Source scanId={scanId} source={contract.source} />
      {preview ? <div className="ce-source" aria-label="Immutable contract source preview">{preview.map((item) => <div key={item.line}>
        <span>{item.line}</span><code>{item.text || " "}</code></div>)}</div> :
        <p className="ce-note">Immutable source preview unavailable for this scan.</p>}
      <ul className="ce-cues">{contract.evidence.map((item, index) => <li key={index}>{item.origin} · {item.producerVersion}</li>)}</ul></div></section>
    <section className="section"><h2>Impact Lab</h2><p className="card muted">No contract-level launch action is available. Impact Lab requires its existing configured RPC, finding or hypothesis, reviewed artifact, and verified local session authority.</p></section>
  </>;
}

export default async function ContractExplorerPage({ params, searchParams }: { params: Promise<{ id: string; contractId: string }>;
  searchParams?: Promise<{ mode?: string }> }) {
  const { id, contractId } = await params;
  if (!contractIdPattern.test(contractId)) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  const loaded = loadProtocolMapForPage(database, id);
  if (!loaded.artifact) notFound();
  const findings = listFindings(database, { scanId: id }).map((item) => ({ id: item.id, title: item.title,
    source: item.source, detectorId: item.detectorId, status: item.status, filePath: item.filePath, startLine: item.startLine }));
  const view = contractExplorerView(loaded.artifact, contractId, findings);
  if (!view) notFound();
  let preview: Array<{ line: number; text: string }> | null = null;
  if (view.contract.source && loaded.artifact.graph.sourceUnits.some((item) =>
    item.sourceUnitName === view.contract.source!.sourceUnitName)) {
    const source = getScanSource(database, id, view.contract.source.sourceUnitName);
    if (source.available) try {
      const lines = new TextDecoder("utf-8", { fatal: true }).decode(source.rawBytes).split(/\r?\n/);
      const start = Math.max(1, view.contract.source.startLine - 2);
      preview = lines.slice(start - 1, start + 11).map((text, index) => ({ line: start + index, text }));
    } catch { preview = null; }
  }
  const mode = (await searchParams)?.mode === "researcher" ? "researcher" : "beginner";
  return <Explorer view={view} repositoryName={scan.repositoryName} preview={preview} mode={mode} />;
}
