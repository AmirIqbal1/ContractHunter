"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import type { AssetFlow, AssetFlowEntry, AttemptedAssetFlow, ImpactScenario } from "@contracthunter/core";

type Position = AssetFlow["netPositions"][number];
type Movement = { id: string; transactionOrdinal: number; transactionHash: string; assetId: string;
  from: string; to: string; amount: string; status: "committed" | "attempted";
  kind: string; evidence: string; entry?: AssetFlowEntry; attempt?: AttemptedAssetFlow };
const PAGE_SIZE = 50;
const GRAPH_LIMIT = 40;
const short = (value: string) => value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
const signed = (value: string) => BigInt(value) > 0n ? `+${value}` : value;
const raw = (value: string) => BigInt(value).toLocaleString("en-US");
const assetName = (asset: AssetFlow["assets"][number] | undefined) => !asset ? "Unknown asset" :
  asset.standard === "native" ? `NATIVE (wei)` :
  `${asset.standard === "token-unknown-standard" ? "TOKEN · UNKNOWN STANDARD" : asset.standard.toUpperCase()} · ${asset.contractAddress ?? "unknown"}${asset.tokenId !== null ? ` · token ID ${asset.tokenId}` : ""}`;

export function AssetFlowView({ flow, executionIds, txPositions, labels, scenarios = [], initialTx, initialAsset,
  initialParticipant, initialStatus, initialMode, initialEntry, investigationHref }: { flow: AssetFlow; executionIds: string[];
  txPositions: Record<number, Position[]>; labels: Record<string, string>; scenarios?: ImpactScenario[]; initialTx?: string;
  initialAsset?: string; initialParticipant?: string; initialStatus?: string; initialMode?: string; initialEntry?: string;
  investigationHref?: string | null }) {
  const router = useRouter();
  const [tx, setTx] = useState(initialTx === "all" || !flow.transactions.some((item) => String(item.ordinal) === initialTx) ? "all" : initialTx!);
  const [assetId, setAssetId] = useState(flow.assets.some((item) => item.id === initialAsset) ? initialAsset! : "all");
  const [participant, setParticipant] = useState(flow.participants.some((item) => item.address === initialParticipant) ? initialParticipant! : "all");
  const [showAttempted, setShowAttempted] = useState(initialStatus === "attempted");
  const [standard, setStandard] = useState("all"), [mapping, setMapping] = useState("all");
  const [search, setSearch] = useState(""), [sort, setSort] = useState("canonical");
  const [page, setPage] = useState(0), [selectedId, setSelectedId] = useState<string | null>(
    flow.ledgerEntries.some((item) => item.id === initialEntry) ? initialEntry! : null);
  const [showUnchanged, setShowUnchanged] = useState(false);
  const [mode, setMode] = useState(initialMode === "researcher" ? "researcher" : "beginner");
  const assets = new Map(flow.assets.map((item) => [item.id, item]));
  const participants = new Map(flow.participants.map((item) => [item.address, item]));
  const base = `/hunts/${encodeURIComponent(flow.scanId)}/impact/executions/${encodeURIComponent(flow.executionId)}`;
  const path = `/hunts/${encodeURIComponent(flow.scanId)}`;
  function urlSet(key: string, value: string) {
    const url = new URL(window.location.href); url.searchParams.set(key, value);
    window.history.replaceState(null, "", `${url.pathname}${url.search}`);
  }
  function person(address: string) {
    const p = participants.get(address);
    const name = p?.contractNodeId ? labels[p.contractNodeId] : null;
    return <><strong>{name ?? p?.label ?? "Unmapped address"}</strong> <span className="mono" title={address}>{mode === "researcher" ? address : short(address)}</span></>;
  }
  function nodeClass(address: string) {
    const label = participants.get(address)?.label;
    return `af-node ${label === "Zero address" ? "af-zero" : label === "Mapped protocol contract" ? "af-mapped" :
      label === "Disposable PoC sender" ? "af-disposable" : "af-unmapped"}`;
  }
  const movements: Movement[] = [
    ...flow.ledgerEntries.map((entry) => ({ id: entry.id, transactionOrdinal: entry.transactionOrdinal,
      transactionHash: entry.transactionHash, assetId: entry.assetId, from: entry.from, to: entry.to,
      amount: entry.amount, status: "committed" as const, kind: entry.movementKind, evidence: entry.evidenceKind, entry })),
    ...flow.attemptedFlows.map((attempt) => ({ id: attempt.id, transactionOrdinal: attempt.transactionOrdinal,
      transactionHash: attempt.transactionHash, assetId: attempt.assetId, from: attempt.from, to: attempt.to,
      amount: attempt.amount, status: "attempted" as const, kind: "native-value", evidence: attempt.reason, attempt }))
  ];
  const term = search.trim().toLowerCase();
  const filtered = movements.filter((item) => {
    const a = assets.get(item.assetId), from = participants.get(item.from), to = participants.get(item.to);
    return (item.status === "committed" || showAttempted) && (tx === "all" || String(item.transactionOrdinal) === tx) &&
      (assetId === "all" || item.assetId === assetId) &&
      (participant === "all" || item.from === participant || item.to === participant) &&
      (standard === "all" || a?.standard === standard) &&
      (mapping === "all" || (mapping === "mapped" ? !!from?.contractNodeId || !!to?.contractNodeId :
        !from?.contractNodeId || !to?.contractNodeId)) &&
      (!term || `${item.from} ${item.to} ${item.transactionHash} ${a?.contractAddress ?? ""} ${from?.contractNodeId ? labels[from.contractNodeId] ?? "" : ""} ${to?.contractNodeId ? labels[to.contractNodeId] ?? "" : ""}`.toLowerCase().includes(term));
  });
  const committed = filtered.filter((item) => item.status === "committed");
  const attempted = filtered.filter((item) => item.status === "attempted");
  const positionSource = tx === "all" ? flow.netPositions : txPositions[Number(tx)] ?? [];
  const positions = positionSource.filter((item) => (assetId === "all" || item.assetId === assetId) &&
    (participant === "all" || item.participant === participant) &&
    (standard === "all" || assets.get(item.assetId)?.standard === standard));
  const reconciliation = flow.reconciliation.filter((item) => (assetId === "all" || item.assetId === assetId) &&
    (participant === "all" || item.participant === participant) &&
    (showUnchanged || item.before !== item.after || item.status === "unavailable"));
  const sorted = sort === "canonical" ? filtered : [...filtered].sort((a, b) => sort === "amount" ?
    BigInt(a.amount) === BigInt(b.amount) ? 0 : BigInt(a.amount) > BigInt(b.amount) ? -1 : 1 :
    sort === "asset" ? a.assetId.localeCompare(b.assetId) : a.from.localeCompare(b.from));
  const pageRows = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const selected = filtered.find((item) => item.id === selectedId);
  const visibleGraph = committed.slice(0, GRAPH_LIMIT);
  const graphGroups: Array<{ key: string; entries: Movement[] }> = [];
  for (const item of visibleGraph) {
    const key = `${item.transactionOrdinal}|${item.assetId}|${item.from}|${item.to}|${item.entry?.orderDomain}`;
    const last = graphGroups.at(-1);
    if (last?.key === key) last.entries.push(item);
    else graphGroups.push({ key, entries: [item] });
  }
  const displayedTxs = tx === "all" ? flow.transactions : flow.transactions.filter((item) => String(item.ordinal) === tx);
  const evidenceMetrics = [
    ["Transactions", flow.summary.transactionCount], ["Committed ledger entries", flow.summary.committedEntryCount],
    ["Attempted flows", flow.summary.attemptedFlowCount], ["Assets", flow.summary.assetCount],
    ["Participants", flow.summary.participantCount], ["Native transfers", flow.summary.nativeTransferCount],
    ["ERC20 transfers", flow.summary.erc20TransferCount], ["ERC721 NFT transfers", flow.summary.nftTransferCount],
    ["ERC1155 transfers", flow.summary.erc1155TransferCount],
    ["Reconciled observations", flow.summary.reconciledObservationCount],
    ["Partial/mismatched observations", flow.summary.partialOrMismatchedObservationCount]
  ] as const;
  return <div className="af-view">
    <header className="page-head"><div><div className="eyebrow">OBSERVED ASSET FLOW · ISOLATED LOCAL FORK</div><h1>Asset Flow</h1>
      <p className="subhead">Derived from committed runtime evidence and PRE/POST observations from this exact local reproduction.</p></div></header>
    <nav className="ip-actions" aria-label="Impact execution views"><Link href={base}>Observed Execution</Link>
      <Link href={`${base}?state=all#observed-state`}>Observed State Changes</Link>
      {investigationHref && <Link href={investigationHref}>Back to Investigation Path</Link>}
      <Link href={`${base}/assets/scenarios/new`}>Create Impact Scenario</Link>
      <Link href={`/hunts/${encodeURIComponent(flow.scanId)}/protocol-map?view=money-flow`}>Compare with Static Money Flow</Link></nav>
    <p>Static Money Flow shows source-backed transfer-like operations. Observed Asset Flow shows committed movement evidence from this one isolated reproduction.</p>
    <div className="sh-mode" aria-label="Display mode">{(["beginner", "researcher"] as const).map((value) =>
      <button key={value} type="button" aria-pressed={mode === value} onClick={() => { setMode(value); urlSet("mode", value); }}>{value === "beginner" ? "Beginner" : "Researcher"}</button>)}</div>
    {mode === "beginner" && <p>Committed movement is supported by successful local execution evidence. Attempted movement did not become committed state. Net observed movement is assets received minus assets sent. Reconciliation checks recorded movements against captured before and after balances.</p>}
    {flow.status === "partial" && <p className="af-warning" role="status"><strong>PARTIAL ASSET ACCOUNTING.</strong> This view contains the movements supported by available evidence. It may not represent every asset movement in the execution.</p>}
    {scenarios.length > 0 && <section className="card"><h2>Impact Scenarios</h2><ul>{scenarios.map((item) =>
      <li key={item.scenarioId}><Link href={`${base}/assets/scenarios/${encodeURIComponent(item.scenarioId)}`}>Scenario {item.scenarioId.slice(0, 8)} · revision {item.revision} · {item.status.toUpperCase()}</Link></li>)}</ul></section>}
    {flow.status === "unavailable" || !flow.capabilities.assetAccountingAvailable ? <section className="card"><h2>Asset accounting unavailable for this execution.</h2><p>Historical or incomplete evidence does not support this accounting view.</p><Link href={base}>Observed Execution</Link> · <Link href={`${base}?state=all#observed-state`}>Observed State Changes</Link></section> : <>
      <section className="card"><h2>Evidence summary</h2><dl className="io-grid">{evidenceMetrics.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>
        {mode === "researcher" && <p className="mono">Schema {flow.schema} · Accounting ruleset {flow.rulesetVersion} · Content SHA-256 {flow.contentSha256} · Execution {flow.executionId} · E1 overlay {flow.provenance.overlayContentSha256}</p>}</section>
      <section className="card"><h2>View controls</h2><div className="io-controls">
        {executionIds.length > 1 && <label>Impact execution <select aria-label="Impact execution" value={flow.executionId} onChange={(event) => { router.push(`/hunts/${encodeURIComponent(flow.scanId)}/impact/executions/${encodeURIComponent(event.target.value)}/assets`); }}>{executionIds.map((id, index) => <option key={id} value={id}>Execution {index + 1} · {short(id)}</option>)}</select></label>}
        <label>Transaction <select aria-label="Transaction" value={tx} onChange={(event) => { setTx(event.target.value); setPage(0); setSelectedId(null); urlSet("tx", event.target.value); }}><option value="all">All transactions</option>{flow.transactions.map((item) => <option key={item.ordinal} value={item.ordinal}>Transaction {item.ordinal + 1}</option>)}</select></label>
        <label>Asset <select aria-label="Asset" value={assetId} onChange={(event) => { setAssetId(event.target.value); setPage(0); urlSet("asset", event.target.value); }}><option value="all">All assets</option>{flow.assets.map((item) => <option key={item.id} value={item.id}>{assetName(item)}</option>)}</select></label>
        <label>Participant <select aria-label="Participant" value={participant} onChange={(event) => { setParticipant(event.target.value); setPage(0); urlSet("participant", event.target.value); }}><option value="all">All participants</option>{flow.participants.map((item) => <option key={item.address} value={item.address}>{labels[item.contractNodeId ?? ""] ?? item.label} · {short(item.address)}</option>)}</select></label>
        <label>Asset type <select value={standard} onChange={(event) => { setStandard(event.target.value); setPage(0); }}><option value="all">All types</option>{["native", "erc20", "erc721", "erc1155", "token-unknown-standard"].map((value) => <option key={value} value={value}>{value === "token-unknown-standard" ? "Unknown token standard" : value.toUpperCase()}</option>)}</select></label>
        <label>Participants <select value={mapping} onChange={(event) => { setMapping(event.target.value); setPage(0); }}><option value="all">All mapping states</option><option value="mapped">Mapped participant involved</option><option value="unmapped">Unmapped participant involved</option></select></label>
        <label>Search evidence <input value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} placeholder="Address, contract, token, tx hash" /></label>
      </div><label><input type="checkbox" checked={showAttempted} onChange={(event) => { setShowAttempted(event.target.checked); setPage(0); urlSet("status", event.target.checked ? "attempted" : "committed"); }} /> Show attempted/reverted flows</label></section>
      <section className="card"><h2>COMMITTED MOVEMENT</h2><p>Directional ledger evidence only. Native trace preorder and receipt-log order are separate; their movements have no inferred combined chronology.</p>
        <p>Showing {visibleGraph.length} of {committed.length} filtered committed ledger entries in the flow view. The ledger below retains every entry.</p>
        <div className="af-flow" role="list" aria-label="Committed directional movements">{graphGroups.map(({ entries: group }) => {
          const first = group[0]!, asset = assets.get(first.assetId);
          const nft = asset?.standard === "erc721";
          const amount = nft ? `${group.length} NFT${group.length === 1 ? "" : "s"} moved` :
            `${raw(group.reduce((sum, item) => sum + BigInt(item.amount), 0n).toString())} ${asset?.standard === "native" ? "wei" : "raw units"}`;
          return <div className="af-edge" role="listitem" key={first.id}><div className={nodeClass(first.from)}>{person(first.from)}</div><div className="af-arrow"><span aria-hidden="true">↓</span><strong>{assetName(asset)}</strong><span>{amount}</span><small>Transaction {first.transactionOrdinal + 1} · {first.kind} · {first.evidence}</small></div><div className={nodeClass(first.to)}>{person(first.to)}</div>
            {group.length > 1 ? <details><summary>View {group.length} canonical entries</summary><ul>{group.map((item) => <li key={item.id}><button type="button" onClick={() => setSelectedId(item.id)}>{item.id} · {item.entry?.tokenId !== null ? `token ID ${item.entry?.tokenId} · ` : ""}{item.amount} raw</button></li>)}</ul></details> : <button type="button" onClick={() => setSelectedId(first.id)}>View ledger entry</button>}</div>;
        })}</div>{committed.length === 0 && <p>No committed asset movements match this view.{tx !== "all" && displayedTxs[0]?.status === "reverted" ? " No committed asset movements from this transaction." : ""}</p>}</section>
      {showAttempted && <section className="card af-attempted"><h2>ATTEMPTED — REVERTED</h2><p>These native value attempts are outside the committed ledger and net positions.</p><ul>{attempted.map((item) => <li key={item.id}><button type="button" onClick={() => setSelectedId(item.id)}>Transaction {item.transactionOrdinal + 1} · {person(item.from)} → {person(item.to)} · {raw(item.amount)} wei · {item.evidence}</button></li>)}</ul>{attempted.length === 0 && <p>No attempted flows match this view.</p>}</section>}
      <section className="card" id="asset-ledger"><h2>LEDGER</h2><p>Canonical order follows E1 transaction/evidence order. Sorting changes presentation only.</p><label>Sort ledger <select value={sort} onChange={(event) => { setSort(event.target.value); setPage(0); }}><option value="canonical">Canonical order</option><option value="amount">Amount</option><option value="asset">Asset</option><option value="participant">Sender</option></select></label>
        <p>Showing {sorted.length ? page * PAGE_SIZE + 1 : 0}–{Math.min((page + 1) * PAGE_SIZE, sorted.length)} of {sorted.length} entries.</p><div className="af-table-wrap"><table><thead><tr><th>Tx</th><th>Asset</th><th>From</th><th>To</th><th>Amount</th><th>Kind</th><th>Evidence</th><th>Status</th><th>Detail</th></tr></thead><tbody>{pageRows.map((item) => <tr key={item.id}><td>{item.transactionOrdinal + 1}</td><td>{assetName(assets.get(item.assetId))}</td><td>{person(item.from)}</td><td>{person(item.to)}</td><td>{item.entry?.standard === "erc721" ? `token ID ${item.entry.tokenId}` : `${raw(item.amount)} ${item.entry?.standard === "native" || item.attempt ? "wei" : "raw"}`}</td><td>{item.kind}</td><td>{item.evidence}</td><td>{item.status === "committed" ? "COMMITTED" : "ATTEMPTED — REVERTED"}</td><td><button type="button" onClick={() => setSelectedId(item.id)}>Inspect</button></td></tr>)}</tbody></table></div><div className="af-pages"><button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page + 1} of {Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))}</span><button type="button" disabled={(page + 1) * PAGE_SIZE >= sorted.length} onClick={() => setPage(page + 1)}>Next</button></div>
        {selected && <aside className="io-detail" aria-live="polite"><h3>Ledger evidence detail</h3><dl className="io-grid"><div><dt>Ledger/attempt ID</dt><dd className="mono">{selected.id}</dd></div><div><dt>Transaction hash</dt><dd className="mono">{selected.transactionHash}</dd></div><div><dt>Asset ID</dt><dd className="mono">{selected.assetId}</dd></div><div><dt>From</dt><dd className="mono">{selected.from}{mode === "researcher" && <button type="button" onClick={() => navigator.clipboard.writeText(selected.from)}>Copy</button>}</dd></div><div><dt>To</dt><dd className="mono">{selected.to}{mode === "researcher" && <button type="button" onClick={() => navigator.clipboard.writeText(selected.to)}>Copy</button>}</dd></div><div><dt>Raw amount</dt><dd className="mono">{selected.amount}{selected.entry?.standard === "erc721" ? " (ledger movement count; token ID below)" : ""}</dd></div><div><dt>Movement / evidence</dt><dd>{selected.kind} · {selected.evidence}</dd></div><div><dt>Status</dt><dd>{selected.status}</dd></div>{selected.entry && <><div><dt>Evidence ID / order domain</dt><dd className="mono">{selected.entry.evidenceId} · {selected.entry.orderDomain}</dd></div><div><dt>Log ID / trace call ID</dt><dd className="mono">{selected.entry.logId ?? "—"} / {selected.entry.runtimeCallId ?? "—"}</dd></div><div><dt>Log index</dt><dd>Unavailable in E1 read model</dd></div><div><dt>Token ID / operator</dt><dd className="mono">{selected.entry.tokenId ?? "—"} / {selected.entry.operator ?? "—"}</dd></div><div><dt>Classification witness</dt><dd className="mono">{selected.entry.classificationEvidenceId ?? "Unavailable"}</dd></div><div><dt>Mapped contract / function</dt><dd className="mono">{selected.entry.mappedContractNodeId ?? "Unresolved"} / {selected.entry.mappedFunctionNodeId ?? "Unresolved"}</dd></div></>}{selected.attempt && <div><dt>Revert reason</dt><dd>{selected.attempt.reason}</dd></div>}</dl>
          <p className="mono">Ruleset {flow.rulesetVersion} · Content SHA-256 {flow.contentSha256} · Overlay {flow.provenance.overlayContentSha256} · Trace hashes {flow.provenance.traceContentSha256.join(", ") || "unavailable"} · PRE {flow.provenance.preSnapshotSha256 ?? "unavailable"} · POST {flow.provenance.postSnapshotSha256 ?? "unavailable"}</p>
          {(selected.entry?.runtimeCallId || selected.attempt?.runtimeCallId) && <Link href={`${base}?tx=${selected.transactionOrdinal}&call=${encodeURIComponent((selected.entry?.runtimeCallId ?? selected.attempt?.runtimeCallId)!)}#observed-execution`}>View in Observed Execution</Link>}
          {selected.entry?.mappedContractNodeId && labels[selected.entry.mappedContractNodeId] && <><Link href={`${path}/contracts/${encodeURIComponent(selected.entry.mappedContractNodeId)}`}>Open Contract Explorer</Link> · <Link href={`${path}/protocol-map?execution=${encodeURIComponent(flow.executionId)}&observed=1`}>Show on Protocol Map</Link></>}
          {selected.entry?.mappedFunctionNodeId && selected.entry.mappedContractNodeId && labels[selected.entry.mappedFunctionNodeId] && <Link href={`${path}/contracts/${encodeURIComponent(selected.entry.mappedContractNodeId)}/functions/${encodeURIComponent(selected.entry.mappedFunctionNodeId)}?execution=${encodeURIComponent(flow.executionId)}`}>Open Function Explorer</Link>}
        </aside>}</section>
      <section className="card"><h2>NET OBSERVED MOVEMENT</h2><p>Received minus sent within {tx === "all" ? "this exact execution" : `Transaction ${Number(tx) + 1}`}. Gross volume is not economic impact. Each asset stays separate.</p><div className="af-table-wrap"><table><thead><tr><th>Participant</th><th>Asset</th><th>Gross incoming</th><th>Gross outgoing</th><th>Net observed movement</th></tr></thead><tbody>{positions.map((item) => <tr key={`${item.participant}:${item.assetId}`}><td>{person(item.participant)}</td><td>{assetName(assets.get(item.assetId))}</td><td className="mono">{item.incoming}</td><td className="mono">{item.outgoing}</td><td className="mono">{signed(item.netObservedMovement)}</td></tr>)}</tbody></table></div>{positions.length === 0 && <p>No committed positions match this view.</p>}</section>
      <section className="card"><h2>RECONCILIATION</h2><p>Reconciliation compares observed directional movements with captured PRE/POST balances. Differences can reflect incomplete observations or token behavior and do not by themselves indicate a vulnerability.</p>
        {tx !== "all" ? <p>PRE/POST observations cover the whole execution; E1 has no transaction-local balance snapshots. Select All transactions to inspect reconciliation.</p> : <><label><input type="checkbox" checked={showUnchanged} onChange={(event) => setShowUnchanged(event.target.checked)} /> Show unchanged</label><div className="af-table-wrap"><table><thead><tr><th>Asset / participant</th><th>PRE</th><th>POST</th><th>Observed delta</th><th>Ledger net</th><th>Difference</th><th>Result</th><th>Observation</th></tr></thead><tbody>{reconciliation.map((item) => <tr key={item.observationId}><td>{assetName(assets.get(item.assetId))}<br />{item.participant ? person(item.participant) : "No participant"}</td><td className="mono">{item.before ?? "UNAVAILABLE"}</td><td className="mono">{item.after ?? "UNAVAILABLE"}</td><td className="mono">{item.observedDelta ?? "UNAVAILABLE"}</td><td className="mono">{item.ledgerNet ?? "UNAVAILABLE"}</td><td className="mono">{item.difference ?? "UNAVAILABLE"}</td><td>{item.status.toUpperCase().replaceAll("-", " ")}</td><td><Link href={`${base}?state=all#obs-${encodeURIComponent(item.observationId)}`}>View State Observation</Link>{mode === "researcher" && <span className="mono"> · {item.observationId} · PRE {item.preSnapshotId} · POST {item.postSnapshotId ?? "UNAVAILABLE"} · {item.coverage}</span>}</td></tr>)}</tbody></table></div>{reconciliation.length === 0 && <p>No changed reconciliation observations match this view.</p>}</>}</section>
      <section className="card"><h2>Execution Cost</h2><p>This is execution cost on the local fork and is not a protocol asset transfer.</p><div className="af-table-wrap"><table><thead><tr><th>Transaction</th><th>Gas used</th><th>Effective gas price</th><th>Local execution gas cost</th></tr></thead><tbody>{displayedTxs.map((item) => <tr key={item.hash}><td>{item.ordinal + 1}</td><td>{item.executionCost.gasUsed ?? "UNAVAILABLE"}</td><td>UNAVAILABLE</td><td>UNAVAILABLE</td></tr>)}</tbody></table></div><p>Effective gas price is absent from D1 evidence, so exact local execution gas cost is unavailable.</p></section>
      <section className="card"><h2>Assets Observed</h2><ul className="af-catalog">{flow.assets.map((item) => <li key={item.id}><button type="button" onClick={() => { setAssetId(item.id); setPage(0); urlSet("asset", item.id); }}>{assetName(item)}</button> · {item.transactions.length} transactions · {item.participantCount} participants{mode === "researcher" && <span className="mono"> · {item.id}</span>}</li>)}</ul></section>
      <section className="card"><h2>Participants</h2><ul className="af-catalog">{flow.participants.map((item) => <li key={item.address}><button type="button" onClick={() => { setParticipant(item.address); setPage(0); urlSet("participant", item.address); }}>{person(item.address)}</button> · {new Set(flow.ledgerEntries.filter((entry) => entry.from === item.address || entry.to === item.address).map((entry) => entry.assetId)).size} assets · {new Set(flow.ledgerEntries.filter((entry) => entry.from === item.address || entry.to === item.address).map((entry) => entry.transactionOrdinal)).size} transactions
        {item.contractNodeId && labels[item.contractNodeId] && <><Link href={`${path}/contracts/${encodeURIComponent(item.contractNodeId)}`}>Open Contract Explorer</Link> · <Link href={`${path}/protocol-map?execution=${encodeURIComponent(flow.executionId)}&observed=1`}>Show on Protocol Map</Link></>}</li>)}</ul></section>
      {flow.warnings.length > 0 && <section className="card af-warning"><h2>Accounting warnings</h2><ul>{flow.warnings.map((warning) => <li key={warning}>{warning.replaceAll("-", " ")}</li>)}</ul></section>}
    </>}
  </div>;
}
