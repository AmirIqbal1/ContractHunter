"use client";

import Link from "next/link";
import { useState } from "react";
import type { ImpactOverlay, ImpactPathComparison, ObservedOverlayCall, ObservedOverlayState, StaticProtocolGraphArtifact } from "@contracthunter/core";

type Identity = { name: string; contractId: string | null; source: { sourceUnitName: string; startLine: number } | null };
const short = (value: string | null) => value && value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value ?? "unknown";
const statusLabel = (value: string) => ({ "observed-static-edge": "OBSERVED IN THIS LOCAL EXECUTION",
  "runtime-only-observed": "RUNTIME-ONLY OBSERVED CALL", "matched-contract-only": "CONTRACT MATCH ONLY",
  "unmapped-runtime-call": "UNMAPPED", "ambiguous-static-edge": "AMBIGUOUS",
  "root-call": "OBSERVED LOCAL CALL", "observed-in-this-local-execution": "OBSERVED IN THIS LOCAL EXECUTION",
  "not-observed-in-this-execution": "NOT OBSERVED IN THIS EXECUTION",
  "comparison-unresolved": "UNAVAILABLE", "static-context-only": "STATIC CONTEXT ONLY" } as Record<string, string>)[value] ?? value;
const localNote = "Observed during a reviewed PoC executed against ContractHunter's isolated local fork.";
const sourceHref = (scanId: string, source: NonNullable<Identity["source"]>) =>
  `/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(source.sourceUnitName)}&line=${source.startLine}`;
function dataSummary(value: ObservedOverlayCall["input"] | null) {
  return value ? <span className="mono">{value.byteLength} bytes · {value.prefix}{value.truncated ? "… (truncated)" : ""} · {value.sha256}</span> : "Unavailable";
}
function stateName(item: ObservedOverlayState) {
  const d = item.descriptor;
  if (item.kind === "native") return `Native balance · ${d.address}`;
  if (item.kind === "erc20") return `ERC20 raw units · token ${d.token} · account ${d.holder}`;
  if (item.kind === "erc721") return `ERC721 owner · token ${d.token} · token ID ${d.tokenId}`;
  if (item.kind === "erc1155") return `ERC1155 amount · token ${d.token} · token ID ${d.tokenId} · account ${d.holder}`;
  if (item.kind === "storage") return `Storage slot ${d.slot} · ${d.contract}`;
  return `Supported view ${d.kind} · ${d.target}`;
}
export function ObservedExecution({ overlay, artifact, initialTx = 0, initialCall = null, initialState = "changed",
  researcher = false, pathId = null, displayComparison = null }: { overlay: ImpactOverlay; artifact?: StaticProtocolGraphArtifact | null;
  initialTx?: number; initialCall?: string | null; initialState?: string; researcher?: boolean; pathId?: string | null;
  displayComparison?: ImpactPathComparison | null }) {
  const [tx, setTx] = useState(overlay.transactions.some((item) => item.ordinal === initialTx) ? initialTx : 0);
  const [callId, setCallId] = useState(overlay.observedCalls.some((item) => item.id === initialCall && item.transactionOrdinal === initialTx) ? initialCall : null);
  const [stateFilter, setStateFilter] = useState(["changed", "unchanged", "unavailable", "all", "balances", "tokens", "storage"].includes(initialState) ? initialState : "changed");
  const [traceFilter, setTraceFilter] = useState("all"), [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState(false);
  const identities = new Map<string, Identity>(artifact?.graph.nodes.map((node) => [node.id,
    { name: node.kind === "function" ? node.signature : node.name, contractId: node.kind === "function" ? node.contractId : null, source: node.source }]) ?? []);
  const transaction = overlay.transactions.find((item) => item.ordinal === tx);
  const calls = overlay.observedCalls.filter((item) => item.transactionOrdinal === tx);
  const visible = calls.filter((item) => {
    const label = identities.get(item.mapping.functionNodeId ?? "")?.name ?? identities.get(item.mapping.contractNodeId ?? "")?.name ?? "";
    const term = search.trim().toLowerCase();
    return (!term || `${label} ${item.from} ${item.to} ${item.callType} ${item.relationshipStatus}`.toLowerCase().includes(term)) &&
      (traceFilter === "all" || traceFilter === "external" && ["CALL", "STATICCALL", "CALLCODE"].includes(item.callType) ||
       traceFilter === "delegatecall" && item.callType === "DELEGATECALL" ||
       traceFilter === "reverted" && item.outcome === "reverted" ||
       traceFilter === "runtime-only" && item.relationshipStatus === "runtime-only-observed" ||
       traceFilter === "unmapped" && !item.mapping.contractNodeId ||
       traceFilter === "mapped" && !!item.staticEdgeId);
  });
  const shown = expanded ? visible : visible.filter((item) => item.depth <= 4).slice(0, 60);
  const selected = calls.find((item) => item.id === callId);
  const states = overlay.observedState.filter((item) => stateFilter === "all" || stateFilter === "changed" && item.state === "changed" ||
    stateFilter === "unchanged" && item.state === "unchanged" || stateFilter === "unavailable" && ["unavailable", "post-unavailable"].includes(item.state) ||
    stateFilter === "balances" && item.kind === "native" || stateFilter === "tokens" && ["erc20", "erc721", "erc1155"].includes(item.kind) ||
    stateFilter === "storage" && item.kind === "storage");
  const comparison = displayComparison ?? overlay.pathComparisons.find((item) => item.pathId === pathId);
  function urlSet(key: string, value: string) { if (typeof window === "undefined") return;
    const url = new URL(window.location.href); url.searchParams.set(key, value);
    window.history.replaceState(null, "", `${url.pathname}${url.search}`); }
  return <div className="io-view">
    <p className="io-local"><strong>LOCAL FORK · ISOLATED LOCAL EXECUTION</strong> · {localNote}</p>
    <p>Static Investigation Path: what source and static analysis show. Observed Local Execution: what this exact reviewed local reproduction executed. Observed State Changes: what changed between PRE and POST observations.</p>
    <div className="io-legend" aria-label="Static and observed legend">{["STATIC RELATIONSHIP", "OBSERVED LOCAL CALL", "RUNTIME-ONLY CALL", "NOT OBSERVED IN THIS EXECUTION", "UNMAPPED RUNTIME TARGET", "OBSERVED STATE CHANGE"].map((item) => <span key={item}>{item}</span>)}</div>
    <section className="card"><h2>Execution evidence summary</h2><dl className="io-grid">
      <div><dt>Transactions</dt><dd>{overlay.coverage.transactionCount}</dd></div><div><dt>Observed calls</dt><dd>{overlay.coverage.observedCallCount}</dd></div>
      <div><dt>Contract-mapped calls</dt><dd>{overlay.coverage.contractMappedCallCount}</dd></div><div><dt>Function-mapped calls</dt><dd>{overlay.coverage.functionMappedCallCount}</dd></div>
      <div><dt>Runtime-only calls</dt><dd>{overlay.observedCalls.filter((item) => item.relationshipStatus === "runtime-only-observed").length}</dd></div>
      <div><dt>Unmapped calls</dt><dd>{overlay.coverage.unmappedCallCount}</dd></div><div><dt>State observations</dt><dd>{overlay.coverage.stateObservationCount}</dd></div>
      <div><dt>Changed observations</dt><dd>{overlay.coverage.changedObservationCount}</dd></div><div><dt>Observed logs</dt><dd>{overlay.observedLogs.length}</dd></div></dl>
      {overlay.coverage.unmappedCallCount > 0 && <p role="status">{overlay.coverage.unmappedCallCount} observed calls could not be mapped to canonical ProtocolGraph contracts or functions.</p>}
      {researcher && <p className="mono">Chain ID: {overlay.forkIdentity.chainId} · Fork block: {overlay.forkIdentity.baseBlockNumber} · Fork hash: {overlay.forkIdentity.baseBlockHash}<br />Execution: {overlay.executionId} · Overlay: {overlay.contentSha256} · Derivation: {overlay.derivationVersion}<br />Target code identities: {Object.entries(overlay.forkIdentity.targetCodeHashes).map(([address, hash]) => `${address} ${hash}`).join(" · ") || "unavailable"}</p>}
    </section>
    {comparison && <section className="card"><h2>Static Investigation Path comparison</h2><ol>{comparison.edges.map((edge) => <li key={edge.edgeId}>
      <strong>Static call relationship</strong> · {statusLabel(edge.status)} {researcher && <span className="mono">{edge.edgeId}</span>}
    </li>)}</ol><p>OBSERVED means the runtime trace contains a call matching this static relationship. A single reproduction does not prove this path can never execute. Unmapped calls leave some comparisons unresolved.</p></section>}
    <section className="card" id="observed-execution"><h2>Observed Local Execution</h2>
      <label>Observed Transaction <select aria-label="Observed Transaction" value={tx} onChange={(event) => { const next = Number(event.target.value); setTx(next); setCallId(null); setExpanded(false); urlSet("tx", String(next)); }}>
        {overlay.transactions.map((item) => <option key={item.ordinal} value={item.ordinal}>Transaction {item.ordinal + 1}</option>)}</select></label>
      {transaction ? <dl className="io-grid"><div><dt>Local tx hash</dt><dd className="mono">{transaction.transactionHash}</dd></div><div><dt>Sender</dt><dd className="mono">{transaction.sender ?? "Unavailable"}</dd></div>
        <div><dt>Target</dt><dd className="mono">{transaction.to ?? "Unavailable"}</dd></div><div><dt>Value (wei)</dt><dd>{transaction.valueWei ?? "Unavailable"}</dd></div>
        <div><dt>Status</dt><dd>{transaction.status === "reverted" ? "REVERTED LOCAL TRANSACTION" : transaction.status === "success" ? "SUCCESSFUL LOCAL TRANSACTION" : "Observed trace unavailable"}</dd></div>
        <div><dt>Local block</dt><dd>{transaction.localBlockNumber ?? "Unavailable"}</dd></div><div><dt>Gas used</dt><dd>{transaction.gasUsed ?? "Unavailable"}</dd></div>
        <div><dt>Call count</dt><dd>{calls.length}</dd></div></dl> : <p>There are no recorded local transactions for this execution.</p>}
      {!overlay.capabilities.traceAvailable && <p role="status">Observed trace unavailable. State observations may still be available.</p>}
      <div className="io-controls"><label>Search observed calls <input value={search} onChange={(event) => setSearch(event.target.value)} /></label>
        <label>Trace filter <select value={traceFilter} onChange={(event) => setTraceFilter(event.target.value)}>{[["all", "All"], ["external", "External Calls"], ["delegatecall", "Delegatecalls"], ["reverted", "Reverted"], ["runtime-only", "Runtime-only"], ["unmapped", "Unmapped"], ["mapped", "Mapped to Static"]].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label></div>
      <ol className="io-tree" aria-label="Observed call tree in runtime order">{shown.map((call) => {
        const name = identities.get(call.mapping.functionNodeId ?? "")?.name ?? identities.get(call.mapping.contractNodeId ?? "")?.name;
        return <li key={call.id} style={{ marginInlineStart: `${Math.min(call.depth, 8) * 1.25}rem` }}><button type="button" aria-pressed={callId === call.id} onClick={() => { setCallId(call.id); urlSet("call", call.id); }}>
          <strong>{call.callType}</strong> → {name ?? (call.to ? short(call.to) : "runtime target unavailable")} · {call.outcome === "reverted" ? "REVERTED" : call.outcome.toUpperCase()} · {statusLabel(call.relationshipStatus)}
          {call.to && !call.mapping.contractNodeId && <span> · RUNTIME TARGET · STATIC IDENTITY UNRESOLVED</span>}
          {researcher && <span> · depth {call.depth} · trace index {call.ordinal}</span>}
        </button></li>;
      })}</ol>
      {visible.length > shown.length && <button type="button" onClick={() => setExpanded(true)}>{visible.length - shown.length} calls hidden · Show all</button>}
      {selected && <aside className="io-detail" aria-live="polite"><h3>Observed Call detail</h3><dl className="io-grid">
        <div><dt>Call type</dt><dd>{selected.callType}{selected.rawCallType ? ` (${selected.rawCallType})` : ""}</dd></div><div><dt>Outcome</dt><dd>{selected.outcome === "reverted" ? "REVERTED" : selected.outcome}</dd></div>
        <div><dt>From</dt><dd className="mono">{selected.from}</dd></div><div><dt>Observed runtime target</dt><dd className="mono">{selected.to ?? "Unavailable"}</dd></div>
        <div><dt>Mapped contract/function</dt><dd>{identities.get(selected.mapping.contractNodeId ?? "")?.name ?? "Static identity unresolved"} / {identities.get(selected.mapping.functionNodeId ?? "")?.name ?? "Function unresolved"}</dd></div>
        <div><dt>Mapping</dt><dd>{statusLabel(selected.relationshipStatus)} · {selected.mapping.reason}</dd></div><div><dt>Selector</dt><dd>{selected.selector ?? "Unavailable"}</dd></div>
        <div><dt>Transaction</dt><dd className="mono">{selected.transactionHash}</dd></div><div><dt>Trace index / depth</dt><dd>{selected.ordinal} / {selected.depth}</dd></div>
        <div><dt>Value (wei)</dt><dd>{selected.valueWei ?? "Unavailable"}</dd></div><div><dt>Input</dt><dd>{dataSummary(selected.input)}</dd></div>
        <div><dt>Output / revert data</dt><dd>{dataSummary(selected.output)}</dd></div><div><dt>Revert metadata</dt><dd>{selected.revertKind ?? "—"} {selected.revertDetail ?? selected.error ?? ""}</dd></div>
      </dl>{["DELEGATECALL", "CALLCODE"].includes(selected.callType) && <p>delegatecall executes target code using the caller&apos;s storage/context. Code target: {selected.codeAddress ?? "unavailable"}. Storage context: {selected.storageContextAddress ?? "unavailable"}.</p>}
      {["CREATE", "CREATE2", "SELFDESTRUCT"].includes(selected.callType) && <p>Observed operation. Static source identity is not inferred from runtime bytecode.</p>}
      {selected.mapping.functionNodeId && identities.get(selected.mapping.functionNodeId)?.source && <Link href={sourceHref(overlay.scanId, identities.get(selected.mapping.functionNodeId)!.source!)}>View Source</Link>}
      {selected.mapping.contractNodeId && <Link href={`/hunts/${encodeURIComponent(overlay.scanId)}/contracts/${encodeURIComponent(selected.mapping.contractNodeId)}`}>Open Contract</Link>}
      {selected.mapping.functionNodeId && selected.mapping.contractNodeId && <Link href={`/hunts/${encodeURIComponent(overlay.scanId)}/contracts/${encodeURIComponent(selected.mapping.contractNodeId)}/functions/${encodeURIComponent(selected.mapping.functionNodeId)}?execution=${encodeURIComponent(overlay.executionId)}`}>Open Function Explorer</Link>}
      <details><summary>WHY THIS MAPS</summary><p>{selected.mapping.reason} · evidence {selected.mapping.evidenceId ?? "unavailable"}. Static edge: {selected.staticEdgeId ?? "unavailable"}.</p></details>
      {researcher && <p className="mono">WHY THIS MAPS · {selected.mapping.reason} · evidence {selected.mapping.evidenceId ?? "unavailable"} · code {selected.mapping.deployedCodeSha256 ?? "unavailable"} · static edge {selected.staticEdgeId ?? "unavailable"} · trace {selected.traceId}</p>}
      {selected.relationshipStatus === "runtime-only-observed" && <p>This call occurred during local execution but was not represented by the current static graph.</p>}
      </aside>}
    </section>
    <section className="card" id="observed-state"><h2>Observed State Changes</h2><p>Observed during this execution. No specific call or function is assigned as the cause.</p>
      {!overlay.capabilities.statePreAvailable ? <p role="status">State diff unavailable; no PRE snapshot was captured.</p> :
        !overlay.capabilities.stateDiffAvailable && <p role="status">POST or state diff unavailable. Available PRE values remain below; no POST value is inferred.</p>}
      <label>State filter <select aria-label="State filter" value={stateFilter} onChange={(event) => { setStateFilter(event.target.value); urlSet("state", event.target.value); }}>
        {[["changed", "Changed"], ["unchanged", "Unchanged"], ["unavailable", "Unavailable"], ["all", "All"], ["balances", "Balances"], ["tokens", "Tokens"], ["storage", "Storage"]].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      {states.length ? (["native", "erc20", "erc721", "erc1155", "storage", "view"] as const).map((kind) => {
        const group = states.filter((item) => item.kind === kind);
        if (!group.length) return null;
        return <div key={kind}><h3>{({ native: "Native balances", erc20: "ERC20", erc721: "ERC721", erc1155: "ERC1155", storage: "Storage", view: "Supported views" })[kind]}</h3><ul className="io-state-list">{group.map((item) => <li key={item.observationId}><strong>{stateName(item)}</strong> · {item.state.toUpperCase()}
        <div className="mono">PRE {item.beforeStatus === "available" ? item.before : `UNAVAILABLE (${item.beforeErrorCode ?? "not captured"})`} → POST {item.afterStatus === "available" ? item.after : `UNAVAILABLE (${item.afterErrorCode ?? "not captured"})`}
          {item.delta !== null && ` · delta ${BigInt(item.delta) > 0n ? "+" : ""}${item.delta}`}</div>
        {item.contractNodeId && <Link href={`/hunts/${encodeURIComponent(overlay.scanId)}/contracts/${encodeURIComponent(item.contractNodeId)}`}>Open Contract</Link>}
        {researcher && <div className="mono">Observation {item.observationId} · PRE {item.preSnapshotId} · POST {item.postSnapshotId ?? "unavailable"}</div>}
      </li>)}</ul></div>; }) : <p>No observations match this filter.</p>}
    </section>
    <section className="card"><h2>Observed Logs · Transaction {tx + 1}</h2>{overlay.observedLogs.some((log) => log.transactionHash === transaction?.transactionHash) ? <ul>{overlay.observedLogs.filter((log) => log.transactionHash === transaction?.transactionHash).map((log) => <li key={log.id}>
      <strong>Unknown/Unmapped log</strong> · emitter {identities.get(log.contractNodeId ?? "")?.name ?? log.address} ({log.address}) · tx {short(log.transactionHash)} · topics {log.topics.join(", ") || "none"} · data {dataSummary(log.data)}
      {researcher && <span className="mono"> · index {log.logIndex} · {log.id}</span>}
    </li>)}</ul> : <p>No observed logs in the captured transactions.</p>}</section>
  </div>;
}
