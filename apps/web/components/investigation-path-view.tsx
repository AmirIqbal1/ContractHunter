"use client";

import Link from "next/link";
import { useState } from "react";
import type { ImpactOverlay, ImpactPathComparison, InvestigationPathResult, ProtocolSourceLocation, StaticProtocolGraphArtifact } from "@contracthunter/core";
import { auditConcepts } from "@contracthunter/core/audit-priority-catalog";
import type { PathNodeDetail } from "@/lib/investigation-path-view";
import { ObservedExecution } from "./observed-execution";

type Path = InvestigationPathResult["paths"][number];
type Step = Path["steps"][number];
type Mode = "beginner" | "researcher";
const kindNames: Record<Path["kind"], string> = {
  "local-context": "Local context", "caller-chain": "Caller chain", "callee-chain": "Callee chain",
  "privilege-context": "Privileged context", "oracle-context": "Oracle dependency",
  "upgrade-context": "Upgrade context", "asset-operation-context": "Asset operation context",
};
const viewNames: Record<string, string> = { "money-flow": "Money Flow", permissions: "Permissions",
  "oracle-flow": "Oracle Flow", "external-calls": "External Calls", upgradeability: "Upgradeability",
  "attack-surface": "Attack Surface", findings: "Findings" };
const warningNames: Record<InvestigationPathResult["warnings"][number], string> = {
  "finding-unmapped": "Finding is not mapped to a canonical ProtocolGraph target.",
  "finding-partially-mapped": "Some subject findings have no exact graph attachment.",
  "subject-links-truncated": "Subject finding membership exceeds the analysis bound.",
  "contract-level-only": "The exact attachment is contract level; no function target was inferred.",
  "unresolved-call-target": "A call target is unresolved; the path stops at the known boundary. Dynamic dispatch may alter runtime behavior.",
  "path-limit-reached": "PATH TRUNCATED — additional static paths may exist beyond the configured analysis bound.",
  "traversal-limit-reached": "PATH TRUNCATED — traversal reached its configured analysis bound.",
  "source-unavailable": "Some source locations are unavailable in this graph.",
  "static-only": "Derived from source and static graph relationships. Runtime behavior may differ.",
};
const cueNames: Record<string, string> = {
  "externally-callable": "Externally callable", "state-changing": "State changing",
  "state-write-before-external-call-source-order": "State write before external call in source order",
  "state-write-after-external-call-source-order": "State write after external call in source order",
  "delegatecall-present": "Delegatecall", "unresolved-external-call": "Unresolved external call",
  "token-transfer": "Token transfer-like operation", "native-value-transfer": "Native value transfer",
  privileged: "Proven control relationship", payable: "Payable", "assembly-present": "Assembly",
  "finding-linked": "Finding linked",
};
const sourceHref = (scanId: string, source: ProtocolSourceLocation) =>
  `/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(source.sourceUnitName)}&line=${source.startLine}`;
const subjectHref = (type: string, id: string) => `/${type === "hypothesis" ? "hypotheses" : `${type}s`}/${encodeURIComponent(id)}`;
const mapHref = (scanId: string, node: PathNodeDetail | undefined, mode: Mode, view?: string) =>
  `/hunts/${encodeURIComponent(scanId)}/protocol-map?mode=${mode}${view ? `&view=${encodeURIComponent(view)}` : ""}` +
  (node && (node.contractId || ["contract", "interface", "library"].includes(node.kind)) ?
    `&node=${encodeURIComponent(node.contractId ?? node.id)}` : "");
export function relationshipLabel(kind: string | null, from?: PathNodeDetail, to?: PathNodeDetail): string {
  if (kind === "calls") return from?.contractId && from.contractId === to?.contractId ? "INTERNAL CALL" : "CALL";
  return ({ "external-call": "EXTERNAL CALL", delegates: "DELEGATECALL", controls: "CONTROL",
    prices: "ORACLE DEPENDENCY", transfers: "TRANSFER-LIKE OPERATION", upgrades: "UPGRADE RELATIONSHIP" } as Record<string, string>)[kind ?? ""] ?? (kind?.replaceAll("-", " ").toUpperCase() ?? "RELATIONSHIP");
}
const conceptKey = (step: Step) => step.uncertainty === "unresolved-target" ? "unresolved-external-call" :
  step.explanationKey === "delegatecall" ? "delegatecall" : step.explanationKey;
function SourceLink({ scanId, source, label = "View Source" }: { scanId: string; source: ProtocolSourceLocation | null; label?: string }) {
  return source ? <Link href={sourceHref(scanId, source)}>{label}</Link> : <span className="muted">Source unavailable</span>;
}
function pathLabel(path: Path, nodes: Map<string, PathNodeDetail>) {
  return `${kindNames[path.kind]} · ${path.steps.map((step) => {
    const node = nodes.get(step.nodeId);
    return `${node?.contractName ? `${node.contractName}.` : ""}${step.label}`;
  }).join(" → ")}`;
}
export function InvestigationPathView({ result, nodes, title, status, confidence, repositoryName,
  initialMode = "beginner", initialPathId = null, initialEdgeId = null, overlay = null, artifact = null,
  executionIds = [], displayComparisons = [], initialView = "static", initialTx = 0, initialCall = null, initialState = "changed" }: {
  result: InvestigationPathResult; nodes: PathNodeDetail[]; title: string; status: string;
  confidence: number | null; repositoryName: string; initialMode?: Mode; initialPathId?: string | null;
  initialEdgeId?: string | null; overlay?: ImpactOverlay | null; artifact?: StaticProtocolGraphArtifact | null;
  executionIds?: string[]; initialView?: "static" | "observed" | "compare"; initialTx?: number;
  initialCall?: string | null; initialState?: string; displayComparisons?: ImpactPathComparison[];
}) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const first = result.paths.find((path) => path.id === initialPathId) ??
    result.paths.find((path) => path.kind === "caller-chain") ?? result.paths.find((path) => path.steps.length > 1) ?? result.paths[0];
  const [pathId, setPathId] = useState(first?.id ?? "");
  const [edgeId, setEdgeId] = useState<string | null>(first?.edgeIds.includes(initialEdgeId ?? "") ? initialEdgeId : null);
  const [mode, setMode] = useState<Mode>(initialMode);
  const [view, setView] = useState<"static" | "observed" | "compare">(overlay ? initialView : "static");
  const path = result.paths.find((item) => item.id === pathId) ?? first;
  const target = path ? byId.get(path.targetNodeId) : nodes.find((node) => result.targetNodeIds.includes(node.id));
  const selectedStep = edgeId ? path?.steps.find((step) => step.viaEdgeId === edgeId) : undefined;
  const selectedFrom = selectedStep && path ? byId.get(path.steps[selectedStep.ordinal - 1]?.nodeId) : undefined;
  const selectedTo = selectedStep ? byId.get(selectedStep.nodeId) : undefined;
  const entryCount = path?.steps.filter((step) => byId.get(step.nodeId)?.entryPoint).length ?? 0;
  const externalCalls = path?.steps.filter((step) => step.relationship === "external-call").length ?? 0;
  const ops = result.operations.filter((operation) => operation.functionId === path?.targetNodeId);
  const assets = ops.filter((operation) => ["token-transfer-like", "native-transfer"].includes(operation.kind)).length;
  const relevantViews = path?.securityViews.filter((view) => Object.hasOwn(viewNames, view)) ?? [];
  const comparison = displayComparisons.find((item) => item.pathId === path?.id) ??
    overlay?.pathComparisons.find((item) => item.pathId === path?.id);
  const observationLabel = (value: string | undefined) => value === "observed-in-this-local-execution" ? "✓ OBSERVED IN THIS LOCAL EXECUTION" :
    value === "not-observed-in-this-execution" ? "○ NOT OBSERVED IN THIS EXECUTION" :
    value === "comparison-unresolved" ? "? UNAVAILABLE — mapping incomplete" : "STATIC CONTEXT ONLY";
  function choosePath(next: string) { setPathId(next); setEdgeId(null); if (typeof window !== "undefined") {
    const url = new URL(window.location.href); url.searchParams.set("path", next);
    window.history.replaceState(null, "", `${url.pathname}${url.search}`); } }
  function chooseMode(next: Mode) { setMode(next); if (typeof window !== "undefined") {
    const url = new URL(window.location.href); url.searchParams.set("mode", next);
    window.history.replaceState(null, "", `${url.pathname}${url.search}`); } }
  return <main className="ip-page">
    <nav aria-label="Breadcrumb" className="ce-breadcrumb"><Link href={`/hunts/${encodeURIComponent(result.scanId)}`}>{repositoryName}</Link><span>/</span>
      <Link href={subjectHref(result.subject.type, result.subject.id)}>{result.subject.type}</Link><span>/</span><strong>Investigation Path</strong></nav>
    <header className="page-head"><div><div className="eyebrow">STATIC INVESTIGATION PATH</div><h1>{title}</h1>
      <p className="subhead">{result.subject.type} · current status: <strong>{status}</strong>{confidence !== null ? ` · current confidence: ${confidence}%` : ""}</p>
      <p className="ip-disclaimer">This view shows static relationships around the subject. It does not prove that a path executes or is exploitable at runtime.</p></div>
      <Link className="button secondary-button" href={subjectHref(result.subject.type, result.subject.id)}>← Back to {result.subject.type}</Link></header>
    <div className="sh-mode" role="group" aria-label="Display mode"><button type="button" aria-pressed={mode === "beginner"} onClick={() => chooseMode("beginner")}>Beginner</button>
      <button type="button" aria-pressed={mode === "researcher"} onClick={() => chooseMode("researcher")}>Researcher</button></div>
    {overlay && <><p className="io-local"><strong>LOCAL FORK</strong> · Observed during a reviewed PoC executed against ContractHunter&apos;s isolated local fork.</p>
      <label>Impact execution <select aria-label="Impact execution" value={overlay.executionId} onChange={(event) => { const url = new URL(window.location.href); url.searchParams.set("execution", event.target.value); window.location.assign(url.toString()); }}>
        {executionIds.map((id, index) => <option key={id} value={id}>Execution {index + 1} · {id.slice(0, 8)}</option>)}</select></label>
      <div className="ip-actions"><Link href={`/hunts/${encodeURIComponent(result.scanId)}/impact/executions/${encodeURIComponent(overlay.executionId)}/assets`}>Asset Flow</Link></div>
      <div className="sh-mode" role="group" aria-label="Evidence view">{(["static", "observed", "compare"] as const).map((item) =>
        <button type="button" key={item} aria-pressed={view === item} onClick={() => { setView(item); const url = new URL(window.location.href); url.searchParams.set("view", item); window.history.replaceState(null, "", `${url.pathname}${url.search}`); }}>
          {item === "static" ? "Static Investigation" : item === "observed" ? "Observed Execution" : "Compare"}</button>)}</div></>}
    {(view !== "observed" || !overlay) && <>
    <section className="card ip-overview"><h2>Target and derivation</h2><dl className="details"><div className="detail"><dt>Subject</dt><dd>{result.subject.type}</dd></div>
      <div className="detail"><dt>Current lifecycle/status</dt><dd>{status}</dd></div><div className="detail"><dt>Affected contract/function</dt>
      <dd>{target ? `${target.contractName ? `${target.contractName}.` : ""}${path?.steps.find((step) => step.nodeId === target.id)?.label ?? target.name}` : "No canonical target"}</dd></div>
      <div className="detail"><dt>Source location</dt><dd>{target?.source ? <SourceLink scanId={result.scanId} source={target.source} label={`${target.source.sourceUnitName}:${target.source.startLine}`} /> : "Unavailable"}</dd></div>
      <div className="detail"><dt>Path derivation</dt><dd>{result.mapping} · {result.coverage}</dd></div></dl>
      {mode === "researcher" && <p className="mono ip-identity">Subject ID: {result.subject.id} · Graph: {result.protocolGraphId}<br />Schema: {result.schema} · Derivation: {result.derivationVersion}<br />Result: {result.contentSha256}</p>}</section>
    {result.warnings.some((warning) => warning !== "static-only") && <section className="ip-warning" role="status"><h2>Analysis limits</h2><ul>{result.warnings.filter((warning) => warning !== "static-only").map((warning) => <li key={warning}>{warningNames[warning]}</li>)}</ul></section>}
    {result.paths.filter((item) => item.kind === "caller-chain").length > 1 && <p className="ip-note">Multiple bounded static caller chains are available. The selected chain is not the only possible runtime route.</p>}
    {result.mapping === "unmapped" ? <section className="card ip-state"><h2>Finding is not mapped to a canonical ProtocolGraph target.</h2>
      <p>No static Investigation Path could be derived from the current graph. This does not establish isolation or safety.</p>
      <Link href={subjectHref(result.subject.type, result.subject.id)}>Return to {result.subject.type}</Link> · <Link href={mapHref(result.scanId, undefined, mode)}>Open Protocol Map</Link></section> :
      !path ? <section className="card ip-state"><h2>No static Investigation Path could be derived from the current graph.</h2>
        <p>Review the exact attachment and source from the subject page.</p><Link href={subjectHref(result.subject.type, result.subject.id)}>Return to {result.subject.type}</Link> · <Link href={mapHref(result.scanId, target, mode)}>Open Protocol Map</Link>
        {target?.source && <> · <SourceLink scanId={result.scanId} source={target.source} /></>}</section> : <>
      <section className="section"><h2>Selected static path</h2><p>Choose among bounded server-derived paths. Ordering follows the Phase 9A result.</p>
        <label className="ip-selector">Investigation Path <select aria-label="Investigation Path" value={path.id} onChange={(event) => choosePath(event.target.value)}>
          {result.paths.map((item, index) => <option value={item.id} key={item.id}>{index + 1}. {pathLabel(item, byId)}</option>)}</select></label>
        <div className="ip-kind-links" aria-label="Path types">{[...new Set(result.paths.map((item) => item.kind))].map((kind) => {
          const firstOfKind = result.paths.find((item) => item.kind === kind)!;
          return <button key={kind} type="button" aria-pressed={path.kind === kind} onClick={() => choosePath(firstOfKind.id)}>{kindNames[kind]}</button>;
        })}</div>
        <p className="ip-coverage"><strong>{kindNames[path.kind]}</strong> · {path.completeness} · {path.steps.length} steps · traversal depth {path.edgeIds.length}</p>
        {view === "compare" && comparison && comparison.runtimeOnlyCallIds.length > 0 &&
          <p className="io-marker">+ {comparison.runtimeOnlyCallIds.length} runtime-only observed call{comparison.runtimeOnlyCallIds.length === 1 ? "" : "s"} in this execution. Inspect the observed call tree for exact targets.</p>}
        {path.completeness !== "complete-within-bounds" && <p className="ip-warning" role="status"><strong>{path.completeness === "truncated" ? "PATH TRUNCATED" : path.completeness === "unresolved" ? "TARGET UNRESOLVED" : "PARTIAL PATH"}</strong> · This static view may omit relationships beyond current evidence or bounds.</p>}
        <div className="ip-layout"><ol className="ip-steps" aria-label="Textual Investigation Path steps">{path.steps.map((step, index) => {
          const node = byId.get(step.nodeId), previous = byId.get(path.steps[index - 1]?.nodeId);
          const isTarget = step.nodeId === path.targetNodeId && step.findingIds.length > 0;
          const concept = node?.entryPoint ? auditConcepts["external-entry-point"] : isTarget ? auditConcepts.finding :
            auditConcepts[conceptKey(step) as keyof typeof auditConcepts] ?? auditConcepts["review-cue"];
          return <li key={`${path.id}:${step.nodeId}`}>
            {index > 0 && <div className="ip-connection"><span aria-hidden="true">↓</span><button type="button" aria-pressed={edgeId === step.viaEdgeId}
              onClick={() => setEdgeId(edgeId === step.viaEdgeId ? null : step.viaEdgeId)}>
              {relationshipLabel(step.relationship, previous, node)} · Why this connection?</button>
              {view === "compare" && comparison && <strong className="io-marker">{observationLabel(comparison.edges[index - 1]?.status)}</strong>}</div>}
            <article className={`card ip-step${isTarget ? " ip-target" : ""}${step.uncertainty === "unresolved-target" ? " ip-unresolved" : ""}`}>
              <div className="ip-step-head"><span className="eyebrow">Step {index + 1} · {step.nodeKind}</span>
                {isTarget && <strong className="ip-marker">FINDING ATTACHED HERE</strong>}
                {node?.entryPoint && <strong className="ip-marker">EXTERNAL ENTRY POINT</strong>}
                {step.uncertainty === "unresolved-target" && <strong className="ip-marker">TARGET UNRESOLVED</strong>}</div>
              <h3>{node?.contractName ? `${node.contractName}.` : ""}{step.label}</h3>
              {view === "compare" && comparison && <p className="io-marker">{observationLabel(comparison.steps[index]?.status)}</p>}
              {node?.entryPoint && <p className="ip-note">This function is externally callable and is statically connected to the finding target through known call relationships.</p>}
              {mode === "beginner" ? <p className="ip-note"><strong>Why this step matters:</strong> {concept.meaning} {concept.why}</p> :
                <p className="mono ip-identity">Node: {step.nodeId} · Edge entering: {step.viaEdgeId ?? "none"}<br />
                  Reasons: {step.reasons.join(", ")} · Finding IDs: {step.findingIds.join(", ") || "none"}</p>}
              {mode === "beginner" && <p className="ip-note"><strong>Included because:</strong> {step.findingIds.length ? "An exact finding link names this graph node." :
                step.viaEdgeId ? `A source-backed ${relationshipLabel(step.relationship, previous, node).toLowerCase()} connects this step.` :
                  "The server included this node in the selected static context."}</p>}
              {step.uncertainty !== "resolved" && <p className="ip-note">{step.uncertainty === "unresolved-target" ? "No target continuation is established." : "Exact source for this step is unavailable."}</p>}
              {node?.source && <p className="ip-source">{node.source.sourceUnitName}:{node.source.startLine}{mode === "researcher" ? `–${node.source.endLine} · bytes ${node.source.startByte ?? "?"}–${node.source.endByte ?? "?"}` : ""}</p>}
              <div className="ip-actions"><SourceLink scanId={result.scanId} source={node?.source ?? null} />
                {node?.contractId && <><Link href={`/hunts/${encodeURIComponent(result.scanId)}/contracts/${encodeURIComponent(node.contractId)}?mode=${mode}`}>Open Contract</Link>
                  <Link href={`/hunts/${encodeURIComponent(result.scanId)}/contracts/${encodeURIComponent(node.contractId)}/functions/${encodeURIComponent(node.id)}?mode=${mode}`}>Open Function</Link></>}
                {node && ["contract", "interface", "library"].includes(node.kind) && <Link href={`/hunts/${encodeURIComponent(result.scanId)}/contracts/${encodeURIComponent(node.id)}?mode=${mode}`}>Open Contract</Link>}
                <Link href={mapHref(result.scanId, node, mode)}>Show on Protocol Map</Link>
                {step.findingIds.map((id) => <Link key={id} href={`/findings/${encodeURIComponent(id)}`}>Open Finding</Link>)}</div>
              {mode === "researcher" && <details><summary>Provenance ({step.provenance.length})</summary><ul>{step.provenance.map((item, i) => <li key={`${item.origin}:${i}`}>
                {item.origin} · {item.producerVersion} · {item.referenceId ?? "no reference ID"}
                {item.source && <> · <SourceLink scanId={result.scanId} source={item.source} label={`${item.source.sourceUnitName}:${item.source.startLine}–${item.source.endLine}`} /></>}</li>)}</ul></details>}
            </article></li>;
        })}</ol>
        <aside className="ip-aside">{selectedStep ? <section className="card" aria-live="polite"><h2>WHY THIS CONNECTION EXISTS</h2>
          <p><strong>{relationshipLabel(selectedStep.relationship, selectedFrom, selectedTo)}</strong></p>
          <p>{selectedFrom?.name ?? "Known source node"} → {selectedTo?.name ?? selectedStep.label}</p>
          <p>Source-backed relationship from the static graph. Reasons: {selectedStep.reasons.join(", ")}.</p>
          <SourceLink scanId={result.scanId} source={selectedStep.source} label="View connection source" />
          <p className="ip-note">Security View context: {relevantViews.map((view) => viewNames[view]).join(", ") || "none attached to this path"}.</p>
          {mode === "researcher" && <div className="mono ip-identity">Edge ID: {selectedStep.viaEdgeId}<ul>{selectedStep.provenance.map((item, i) =>
            <li key={`${item.origin}:${i}`}>{item.origin}/{item.producerVersion} · {item.referenceId ?? "no reference ID"}</li>)}</ul></div>}
        </section> : <section className="card"><h2>Why this connection?</h2><p>Select a labeled connection in the step list to inspect its source and provenance.</p></section>}
        <section className="card"><h2>Path summary</h2><dl className="ip-summary"><div><dt>Type</dt><dd>{kindNames[path.kind]}</dd></div><div><dt>Steps</dt><dd>{path.steps.length}</dd></div>
          <div><dt>External entry points</dt><dd>{entryCount}</dd></div><div><dt>External calls</dt><dd>{externalCalls}</dd></div>
          <div><dt>Unresolved targets</dt><dd>{path.steps.filter((step) => step.uncertainty === "unresolved-target").length}</dd></div>
          <div><dt>Asset operations at target</dt><dd>{assets}</dd></div><div><dt>Control relationships</dt><dd>{path.steps.filter((step) => step.relationship === "controls").length}</dd></div>
          <div><dt>Oracle relationships</dt><dd>{path.kind === "oracle-context" ? path.edgeIds.length : path.steps.filter((step) => step.relationship === "prices").length}</dd></div></dl></section></aside></div>
      </section>
      {ops.length > 0 && <section className="card"><h2>Source-backed target operations</h2><ul className="ip-operation-list">{ops.map((operation) => <li key={operation.operationId}>
        <strong>{operation.kind.replaceAll("-", " ")}</strong> · {operation.resolution} · <SourceLink scanId={result.scanId} source={operation.source} />
        {mode === "researcher" && <span className="mono"> · {operation.operationId}</span>}</li>)}</ul>
        <p className="ip-note">Operation references describe the attached function; they are not extra path edges.</p></section>}
      {target?.reviewCues.length ? <section className="card"><h2>REVIEW CUES</h2><p>Deterministic Function Explorer facts for the exact target. They do not establish a vulnerability.</p>
        <ul>{target.reviewCues.map((cue) => <li key={cue}>{cueNames[cue] ?? cue}</li>)}</ul></section> : null}
      {!!relevantViews.length && <section className="card"><h2>Relevant Security Views</h2><div className="ip-actions">{relevantViews.map((view) =>
        <Link key={view} href={mapHref(result.scanId, target, mode, view)}>{view === "findings" ? "Open Findings View" : `Open ${viewNames[view]}`}</Link>)}</div></section>}
      {mode === "beginner" && <section className="card"><h2>WHAT TO REVIEW NEXT</h2><ol><li>Open the affected function or contract and read its source.</li>
        <li>Choose local context, caller chain and callee chain where available.</li><li>Inspect labeled calls and relevant Security Views.</li>
        <li>Review attached findings in their current status.</li><li>Use Impact Lab only through an existing eligible workflow with its own review authority.</li></ol></section>}
      </>}
    </>}
    {overlay && view !== "static" ? <ObservedExecution overlay={overlay} artifact={artifact} pathId={path?.id}
      displayComparison={comparison} researcher={mode === "researcher"} initialTx={initialTx} initialCall={initialCall} initialState={initialState} /> :
      !overlay && <section className="card ip-future"><h2>Observed data</h2><p>Observed trace unavailable. State diff unavailable for this subject.</p></section>}
  </main>;
}
