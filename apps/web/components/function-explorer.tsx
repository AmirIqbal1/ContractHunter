"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { FunctionExplorerModel, FunctionOperation, ProtocolSourceLocation } from "@contracthunter/core";
import type { FunctionExplorerResponse } from "@/lib/function-explorer-server";

export type FunctionFinding = { id: string; title: string; source: string; detectorId: string | null; status: string };
export type FlowFilter = "all" | "state" | "calls" | "transfers" | "conditions" | "permissions" | "findings";
export type DisplayMode = "beginner" | "researcher";
const filters: FlowFilter[] = ["all", "state", "calls", "transfers", "conditions", "permissions", "findings"];
const significant = new Set<FunctionOperation["kind"]>(["condition", "revert", "state-write", "internal-call",
  "external-call", "low-level-call", "staticcall", "delegatecall", "token-transfer-like", "native-transfer",
  "assembly", "branch", "loop", "try-catch"]);
const callKinds = new Set<FunctionOperation["kind"]>(["internal-call", "external-call", "low-level-call", "staticcall", "delegatecall"]);
const cueHelp: Record<FunctionExplorerModel["reviewCues"][number], [string, string]> = {
  "externally-callable": ["Externally callable", "Inspect the entry point and its authorization conditions."],
  "state-changing": ["State changing", "Inspect which state variables are written and under which runtime paths."],
  "state-write-before-external-call-source-order": ["State write before external call in source order", "Compare this source position with branches and actual runtime paths."],
  "state-write-after-external-call-source-order": ["State write after external call in source order", "External calls may transfer control before this write. Review protections and actual runtime paths."],
  "delegatecall-present": ["Delegatecall present", "Inspect the target and storage context; this does not establish a proxy or a bug."],
  "unresolved-external-call": ["Unresolved external call", "Inspect how the runtime target is selected."],
  "token-transfer": ["Token-transfer-like operation", "Inspect the call target and asset identity; this fact does not establish a money flow."],
  "native-value-transfer": ["Native-value transfer", "Inspect the value expression and receiver in source."],
  privileged: ["Proven control relationship", "Inspect the exact role check and protected function."],
  payable: ["Payable function", "This function can receive native currency. Inspect how value is handled."],
  "assembly-present": ["Inline assembly", "Low-level EVM/Yul code may need direct source review."],
  "finding-linked": ["Finding linked", "Open the exact ContractHunter finding and assess it separately."],
};
const operationHelp: Partial<Record<FunctionOperation["kind"], string>> = {
  modifier: "A modifier is applied at entry. Its name alone does not prove authorization semantics.",
  condition: "A condition appears in source. Its exact runtime effect has not been proven here.",
  revert: "A revert construct appears in source. It may terminate a runtime path.",
  "state-read": "Reads a state variable stored on-chain. Phase 3 may collapse repeated access sites.",
  "state-write": "Changes contract state stored on-chain. No resulting value is inferred.",
  "internal-call": "Calls another known function in this protocol source.",
  "external-call": "Calls code outside this function. Control may temporarily leave the contract.",
  "low-level-call": "Uses a low-level call; inspect the target and return handling.",
  staticcall: "Calls external code without permitting state changes in that call context.",
  delegatecall: "Runs another contract's code using this contract's storage and context.",
  "token-transfer-like": "A token-transfer-like operation is present; exact asset and direction may be unresolved.",
  "native-transfer": "A native-value-moving operation is present; profit or loss is not inferred.",
  "event-emission": "Emits an event in source; this is not a runtime receipt log.",
  assembly: "Low-level EVM/Yul code is present. Static interpretation may be less complete.",
  branch: "A branch marker; this view does not prove which branch executes.",
  loop: "A loop marker; contained operations may repeat at runtime.",
  "try-catch": "A try/catch marker; this view does not prove which outcome occurs.",
  return: "A return construct appears in source.",
};
export function functionSourceHref(scanId: string, source: ProtocolSourceLocation): string {
  return `/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(source.sourceUnitName)}&line=${source.startLine}`;
}
export function functionHref(scanId: string, contractId: string, functionId: string): string {
  return `/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(contractId)}/functions/${encodeURIComponent(functionId)}`;
}
export function filterFunctionOperations(operations: readonly FunctionOperation[], filter: FlowFilter, query: string,
  compact: boolean): FunctionOperation[] {
  const needle = query.trim().toLocaleLowerCase();
  return operations.filter((item) => {
    const category = filter === "all" || filter === "state" && ["state-read", "state-write"].includes(item.kind) ||
      filter === "calls" && callKinds.has(item.kind) ||
      filter === "transfers" && ["token-transfer-like", "native-transfer"].includes(item.kind) ||
      filter === "conditions" && ["condition", "revert", "branch", "loop", "try-catch", "return"].includes(item.kind) ||
      filter === "permissions" && item.kind === "modifier";
    return category && (!compact || significant.has(item.kind)) &&
      (!needle || `${item.kind} ${item.detail ?? ""} ${item.source.sourceUnitName}`.toLocaleLowerCase().includes(needle));
  });
}
const label = (kind: FunctionOperation["kind"], unresolved: boolean) =>
  kind === "external-call" && unresolved ? "External call — target unresolved" :
    kind === "token-transfer-like" ? "Token transfer-like operation" :
      kind === "event-emission" ? "Event" : kind === "branch" ? "Branch / IF" :
        kind === "loop" ? "Loop" : kind.replaceAll("-", " ");

export function FunctionExplorer({ data, findings, repositoryName, initialOperation = null,
  initialFilter, initialMode, overlay = null, executionIds = [], callComparison = [] }: { data: FunctionExplorerResponse; findings: FunctionFinding[]; repositoryName: string;
  initialOperation?: string | null; initialFilter?: string; initialMode?: string;
  overlay?: import("@contracthunter/core").ImpactOverlay | null; executionIds?: string[];
  callComparison?: Array<{ edgeId: string; status: "observed" | "not-observed" | "unavailable" }> }) {
  const { model } = data, scanId = model.scanId;
  const [mode, setMode] = useState<DisplayMode>(initialMode === "researcher" ? "researcher" : "beginner");
  const [filter, setFilter] = useState<FlowFilter>(filters.includes(initialFilter as FlowFilter) ? initialFilter as FlowFilter : "all");
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(model.operations.some((item) => item.id === initialOperation) ? initialOperation : null);
  const [showAll, setShowAll] = useState(false);
  const [compact, setCompact] = useState(model.operations.length > 80);
  const selected = model.operations.find((item) => item.id === selectedId) ?? null;
  const nodes = useMemo(() => new Map(data.relatedNodes.map((node) => [node.id, node])), [data.relatedNodes]);
  const filtered = useMemo(() => filterFunctionOperations(model.operations, filter, query, compact && !showAll),
    [model.operations, filter, query, compact, showAll]);
  const visible = showAll ? filtered : filtered.slice(0, 80);
  const contractHref = `/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(model.contractId)}`;
  const mapHref = `/hunts/${encodeURIComponent(scanId)}/protocol-map?node=${encodeURIComponent(model.contractId)}`;
  const setUrl = (operation: string | null, nextMode: DisplayMode, nextFilter: FlowFilter) => {
    if (typeof window === "undefined") return;
    const url = new URL(window.location.href);
    if (operation) url.searchParams.set("operation", operation); else url.searchParams.delete("operation");
    if (nextMode !== "beginner") url.searchParams.set("mode", nextMode); else url.searchParams.delete("mode");
    if (nextFilter !== "all") url.searchParams.set("filter", nextFilter); else url.searchParams.delete("filter");
    window.history.replaceState(null, "", `${url.pathname}${url.search}`);
  };
  const select = (id: string) => { setSelectedId(id); setUrl(id, mode, filter); };
  const sourceLink = (source: ProtocolSourceLocation) => <Link className="muted-link mono" href={functionSourceHref(scanId, source)}>
    {source.sourceUnitName}:{source.startLine}{source.endLine !== source.startLine ? `–${source.endLine}` : ""} ↗</Link>;
  const targetLinks = (operation: FunctionOperation) => {
    const fn = operation.targetFunctionId ? nodes.get(operation.targetFunctionId) : undefined;
    const targetContract = operation.targetContractId ? nodes.get(operation.targetContractId) : undefined;
    return operation.resolution === "unresolved" ? <span className="fe-unresolved">Target not statically resolved</span> :
      <span className="fe-links">{fn?.kind === "function" && fn.contractId &&
        <Link href={functionHref(scanId, fn.contractId, fn.id)}>Open function: {fn.signature}</Link>}
        {targetContract && ["contract", "interface", "library"].includes(targetContract.kind) &&
          <Link href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(targetContract.id)}`}>Open contract: {targetContract.name}</Link>}
        {targetContract && <Link href={`/hunts/${encodeURIComponent(scanId)}/protocol-map?node=${encodeURIComponent(targetContract.id)}`}>Show target on Protocol Map</Link>}</span>;
  };
  const sourceLines = data.sourcePreview?.split(/\r?\n/) ?? null;
  const summary = model.summary;
  return <>
    <nav className="ce-breadcrumb" aria-label="Breadcrumb"><Link href={`/hunts/${encodeURIComponent(scanId)}`}>{repositoryName}</Link><span>/</span>
      <Link href={`/hunts/${encodeURIComponent(scanId)}/protocol-map`}>Protocol Map</Link><span>/</span>
      <Link href={contractHref}>{model.contract.name}</Link><span>/</span><strong>{model.function.signature}</strong></nav>
    <header className="page-head"><div><div className="eyebrow">Function Explorer / static source analysis</div>
      <h1>{model.contract.name}.{model.function.signature}</h1><p className="subhead mono">{model.function.source.sourceUnitName}:{model.function.source.startLine}</p>
      <div className="ce-tags"><span>{model.function.visibility}</span><span>{model.function.mutability}</span>
        <span>declared in {model.contract.name}</span><span>{model.findings.length} findings</span>
        {model.function.entryPoint === "yes" && <span>external entry point</span>}
        {data.provenProxy && <span>proven proxy</span>}</div></div>
      <Link className="button secondary-button" href={contractHref}>← Back to Contract Explorer</Link></header>
    <div className="ce-actions">{sourceLink(model.function.source)}<Link className="muted-link" href={mapHref}>Show Contract on Protocol Map →</Link></div>
    {model.function.entryPoint === "yes" && <p className="fe-entry">External entry point: this function can be called from outside the contract. Modifiers or other checks may restrict it.</p>}
    {model.function.mutability === "payable" && <p className="fe-entry">Payable: this function can receive native currency.</p>}
    <div className="fe-warning" role="note"><strong>SOURCE-ORDER VIEW</strong><p>Static source-order view. Actual runtime paths can differ because of branches, loops and dynamic calls. This is not an execution trace or a control-flow graph.</p></div>
    {model.analysisStatus !== "complete" && <div className="pm-warning" role="status"><strong>Partial analysis.</strong> Known facts remain visible; missing or collapsed facts must not be read as absence of behavior.</div>}
    {model.warnings.filter((warning) => warning !== "source-order-only").length > 0 &&
      <ul className="fe-warnings">{model.warnings.filter((warning) => warning !== "source-order-only").map((warning) => <li key={warning}>{warning.replaceAll("-", " ")}</li>)}</ul>}
    <section className="section"><h2>Factual summary</h2><div className="ce-metrics">
      {Object.entries(summary).map(([name, count]) => <div key={name}><span>{name.replace(/([A-Z])/g, " $1")}</span><strong>{count}</strong></div>)}
    </div></section>
    <section className="section"><h2>Modifiers and permissions</h2><div className="card">
      {model.modifiers.length ? <ul className="ce-cues">{model.modifiers.map((item, index) => <li key={`${item.name}:${index}`}>
        <strong className="mono">{item.name}</strong> {item.source && sourceLink(item.source)}</li>)}</ul> : <p className="muted">No applied modifier was extracted.</p>}
      {data.controls.length ? <ul className="ce-cues">{data.controls.map((control) => <li key={control.edgeId}>Proven control relationship: <strong>{control.roleName}</strong> {model.controls.find((item) => item.edgeId === control.edgeId) && sourceLink(model.controls.find((item) => item.edgeId === control.edgeId)!.source)}</li>)}</ul> :
        <p className="ce-note">No role/control relationship was proven. Modifier names alone do not establish authorization.</p>}
    </div></section>
    <section className="section"><h2>Review Cues</h2><div className="card"><p className="ce-note">These facts guide review; they do not establish a vulnerability, severity or exploitability.</p>
      {model.reviewCues.length || summary.lowLevelCalls ? <ul className="fe-cues">{model.reviewCues.map((cue) => <li key={cue}>
        <strong>{cueHelp[cue][0]}</strong><span>{cueHelp[cue][1]}</span></li>)}
        {summary.lowLevelCalls > 0 && <li><strong>Low-level call present</strong><span>Inspect target selection and return handling.</span></li>}</ul> :
        <p className="muted">No specific review cues were derived.</p>}</div></section>
    <section className="section"><div className="section-head"><h2>Source-order operation flow</h2><span className="muted">Showing {visible.length} of {model.operations.length} operations</span></div>
      <div className="fe-tools"><div role="group" aria-label="Display mode" className="fe-toggle">
        {(["beginner", "researcher"] as const).map((value) => <button key={value} type="button" aria-pressed={mode === value}
          onClick={() => { setMode(value); setUrl(selectedId, value, filter); }}>{value === "beginner" ? "Beginner" : "Researcher"}</button>)}</div>
        <label>Filter operations <select value={filter} onChange={(event) => {
          const value = event.target.value as FlowFilter; setFilter(value); setUrl(selectedId, mode, value);
        }}>{filters.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select></label>
        <label>Search operations <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="variable, callee, source" /></label>
        {model.operations.length > 80 && <label className="fe-check"><input type="checkbox" checked={compact && !showAll}
          onChange={(event) => { setCompact(event.target.checked); setShowAll(!event.target.checked); }} />Security-relevant operations first</label>}
      </div>
      {filter === "findings" && <p className="fe-warning">Findings are linked to this function, not to individual operations. See the Findings section below.</p>}
      {model.operations.length ? <div className="fe-workspace"><div className="fe-flow">
        <div className="fe-start"><span>{model.function.entryPoint === "yes" ? "External caller" : "Known static callers"}</span><strong>{model.function.signature}</strong></div>
        <ol className="fe-operations">{visible.map((operation) => <li key={operation.id} className="fe-step" data-kind={operation.kind}>
          <button type="button" className={`fe-operation ${selectedId === operation.id ? "is-selected" : ""}`}
            aria-label={`Select ${label(operation.kind, operation.resolution === "unresolved")} at line ${operation.source.startLine}`}
            aria-pressed={selectedId === operation.id} onClick={() => select(operation.id)}>
            <span className="fe-ordinal">{operation.ordinal + 1}</span><span className="fe-op-body"><span className="fe-op-kind">{label(operation.kind, operation.resolution === "unresolved")}</span>
              <span className="fe-op-detail mono">{operation.detail ?? (operation.resolution === "unresolved" ? "Target unresolved" : "Source-linked fact")}</span>
              {mode === "beginner" && <span className="fe-help">{operationHelp[operation.kind] ?? "Source-backed static operation."}</span>}
              <span className="fe-op-source">{operation.source.sourceUnitName}:{operation.source.startLine}</span></span></button>
          <div className="fe-step-links">{sourceLink(operation.source)}{callKinds.has(operation.kind) && targetLinks(operation)}</div>
        </li>)}</ol>
        {!visible.length && <p className="card muted">No operations match this presentation filter. The underlying model is unchanged.</p>}
        {!showAll && filtered.length > 80 && <button className="button secondary-button" type="button" onClick={() => setShowAll(true)}>Show all {filtered.length} matching operations</button>}
        {compact && !showAll && <p className="ce-note">Simple reads and other details may be collapsed. Switch off the compact option to inspect all operations.</p>}
      </div><aside className="fe-detail" aria-label="Selected operation details">
        {selected ? <><span className="eyebrow">Selected operation</span><h3>{label(selected.kind, selected.resolution === "unresolved")}</h3>
          <p className="mono fe-detail-text">{selected.detail ?? "No bounded expression text available."}</p>
          <dl><dt>Source-order position</dt><dd>{selected.ordinal + 1}</dd><dt>Resolution</dt><dd>{selected.resolution}</dd>
            <dt>Source</dt><dd>{sourceLink(selected.source)}</dd><dt>Origin</dt><dd>{selected.origin}</dd>
            {mode === "researcher" && <><dt>Operation ID</dt><dd className="mono">{selected.id}</dd>
              <dt>Source identity</dt><dd className="mono">{selected.source.sourceUnitName}:{selected.source.startByte ?? "?"}–{selected.source.endByte ?? "?"}</dd>
              <dt>Expression SHA-256</dt><dd className="mono">{selected.detailSha256 ?? "unavailable"}</dd></>}</dl>
          {selected.detailTruncated && <p className="ce-note">Expression preview is truncated; use the source link for full text.</p>}
          {callKinds.has(selected.kind) && targetLinks(selected)}
          {["state-read", "state-write"].includes(selected.kind) && selected.targetContractId &&
            <p className="ce-note">Declaring contract: {nodes.get(selected.targetContractId)?.name ?? "identity unresolved"}.</p>}
          {selected.kind === "delegatecall" && <p className="ce-note">{data.provenProxy ? "A separate proven proxy characteristic exists for this contract." : "No proxy relationship proven from current static evidence."}</p>}
          {selected.kind === "token-transfer-like" && <p className="ce-note">Token identity unresolved unless the exact graph target proves it.</p>}
          {selected.kind === "native-transfer" && <p className="ce-note">The 6A model does not capture a symbolic value amount; inspect the source expression.</p>}
          </> : <p className="muted">Select an operation to inspect source, resolution and provenance.</p>}
      </aside></div> : <p className="card muted">No source-order operations were extracted. Review the analysis warnings and source directly.</p>}
    </section>
    <section className="section"><h2>Function source</h2>{sourceLines ? <div className="card fe-source" aria-label="Immutable function source preview">
      {sourceLines.map((text, index) => <div key={index} className={selected && selected.source.startLine <= model.function.source.startLine + index &&
        selected.source.endLine >= model.function.source.startLine + index ? "is-highlighted" : ""}>
        <span>{model.function.source.startLine + index}</span><code>{text || " "}</code></div>)}
      {data.sourcePreviewTruncated && <p className="ce-note">Preview capped at 4 KiB. Open the immutable source snapshot for the full function.</p>}</div> :
      <p className="card muted">Immutable source preview unavailable. Exact source links remain available.</p>}</section>
    <section className="section"><h2>Called By</h2><ul className="ce-list">{model.callers.map((item) => {
      const caller = item.fromFunctionId ? nodes.get(item.fromFunctionId) : undefined;
      return <li key={item.edgeId}><span>{caller?.signature ?? "Caller function unresolved"} · {item.kind}</span>
        {sourceLink(item.source)}{mode === "researcher" && <small>Evidence: {item.evidenceOrigins.join(", ")}</small>}
        {caller?.kind === "function" && caller.contractId && <Link className="muted-link" href={functionHref(scanId, caller.contractId, caller.id)}>Open function →</Link>}</li>;
    })}</ul>{!model.callers.length && <p className="ce-note">No exact static caller was resolved. External reachability is shown separately above.</p>}</section>
    <section className="section"><h2>Calls</h2><ul className="ce-list">{model.callees.map((item) => {
      const target = item.toFunctionId ? nodes.get(item.toFunctionId) : undefined;
      return <li key={item.edgeId}><span>{target?.signature ?? "Target not statically resolved"} · {item.kind}</span>
        {sourceLink(item.source)}{mode === "researcher" && <small>Evidence: {item.evidenceOrigins.join(", ")}</small>}
        {target?.kind === "function" && target.contractId && <Link className="muted-link" href={functionHref(scanId, target.contractId, target.id)}>Open function →</Link>}</li>;
    })}</ul>{!model.callees.length && <p className="ce-note">No exact static callee was resolved.</p>}</section>
    <section className="section"><h2>Findings</h2>{findings.length ? <ul className="ce-list">{findings.map((finding) => <li key={finding.id}>
      <div><Link className="muted-link" href={`/findings/${finding.id}`}>{finding.title}</Link><div className="ce-meta">{finding.detectorId ?? finding.source} · {finding.status}</div></div></li>)}</ul> :
      <p className="card muted">No exact function finding is attached.</p>}
      {model.findings.length > 0 && <p className="ce-note">Finding identity is exact at function level. No operation-level source mapping is claimed.</p>}</section>
    {mode === "researcher" && <section className="section"><h2>Extraction provenance</h2><ul className="ce-list">
      {model.provenance.map((item) => <li key={`${item.origin}:${item.version}`}>{item.origin} · {item.version}</li>)}</ul></section>}
    <section className="section"><h2>Observed Execution</h2><p className="card">SOURCE-ORDER VIEW above is static. OBSERVED RUNTIME ORDER below describes only one reviewed reproduction on a LOCAL FORK.</p>
      {executionIds.length > 0 && <label>Impact execution <select aria-label="Impact execution" value={overlay?.executionId ?? ""} onChange={(event) => { const url = new URL(window.location.href); url.searchParams.set("execution", event.target.value); window.location.assign(url.toString()); }}>
        <option value="">Choose an execution</option>{executionIds.map((id, index) => <option key={id} value={id}>Execution {index + 1} · {id.slice(0, 8)}</option>)}</select></label>}
      {overlay ? <div className="card"><p><strong>LOCAL FORK</strong> · Observed during a reviewed PoC executed against ContractHunter&apos;s isolated local fork.</p>
        <ol>{overlay.observedCalls.filter((call) => call.mapping.functionNodeId === model.functionId).map((call) => <li key={call.id}>
          OBSERVED {call.callType} · transaction {call.transactionOrdinal + 1} · trace index {call.ordinal} · {call.outcome.toUpperCase()}
          {mode === "researcher" && <span className="mono"> · {call.from} → {call.to} · {call.selector ?? "selector unavailable"}</span>}
        </li>)}</ol>
        {model.callees.length > 0 && <><h3>Static call relationships compared with this execution</h3><ul>{model.callees.map((edge) => <li key={edge.edgeId}>
          {edge.kind.toUpperCase()} → {nodes.get(edge.toFunctionId ?? "")?.signature ?? "target unresolved"} · {callComparison.find((item) => item.edgeId === edge.edgeId)?.status === "observed" ?
            "✓ OBSERVED IN THIS LOCAL EXECUTION" : callComparison.find((item) => item.edgeId === edge.edgeId)?.status === "not-observed" ?
              "NOT OBSERVED IN THIS EXECUTION" : "UNAVAILABLE — mapping incomplete"}
          {mode === "researcher" && <span className="mono"> · {edge.edgeId}</span>}</li>)}</ul>
          <p>A single reproduction does not prove this path can never execute.</p></>}
        <p>Static operation IDs are not assigned to trace calls. State change observed in the execution; exact operation attribution not proven.</p>
        <Link href={`/hunts/${encodeURIComponent(scanId)}/impact/executions/${encodeURIComponent(overlay.executionId)}`}>Inspect Observed Local Execution →</Link></div> :
        <p className="card muted">No exact function mapping is available for the selected execution. Static operations remain source-order facts; no operation is marked executed without authoritative mapping.</p>}
    </section>
  </>;
}
