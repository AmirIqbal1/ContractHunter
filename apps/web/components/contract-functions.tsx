"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import type { ExplorerFunction } from "@/lib/contract-explorer";

type Filter = "all" | "entry" | "findings" | "external" | "state" | "payable";
export function filterContractFunctions(items: readonly ExplorerFunction[], query: string, filter: Filter) {
  const needle = query.trim().toLocaleLowerCase();
  return items.filter(({ node, facts, findings }) =>
    (!needle || node.signature.toLocaleLowerCase().includes(needle)) &&
    (filter === "all" || filter === "entry" && node.entryPoint === "yes" ||
      filter === "findings" && findings.length > 0 ||
      filter === "external" && (node.characteristics.some((item) => item.kind === "external-call") ||
        (facts?.lowLevelCalls.length ?? 0) > 0) ||
      filter === "state" && (facts?.stateWrites.length ?? 0) > 0 ||
      filter === "payable" && node.mutability === "payable"));
}
export function ContractFunctions({ items, scanId }: { items: readonly ExplorerFunction[]; scanId: string }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [limit, setLimit] = useState(60);
  const shown = useMemo(() => filterContractFunctions(items, query, filter), [items, query, filter]);
  return <section className="section" id="functions"><div className="section-head"><h2>Functions</h2><span className="muted">{shown.length} of {items.length}</span></div>
    <div className="ce-tools"><label>Search signatures <input value={query} onChange={(event) => { setQuery(event.target.value); setLimit(60); }} placeholder="withdraw(uint256)" /></label>
      <label>Filter <select value={filter} onChange={(event) => { setFilter(event.target.value as Filter); setLimit(60); }}>
        <option value="all">All functions</option><option value="entry">Entry points</option>
        <option value="findings">With findings</option><option value="external">External calls</option>
        <option value="state">Known state writes</option><option value="payable">Payable</option>
      </select></label></div>
    <ul className="ce-list">{shown.slice(0, limit).map(({ node, facts, findings }) => <li key={node.id} id={`function-${node.id}`}>
      <div><strong className="mono">{node.signature}</strong> {node.entryPoint === "yes" && <span className="badge green">Entry point</span>}
        {findings.length > 0 && <a className="badge amber" href="#findings">{findings.length} findings</a>}
        <div className="ce-meta">{node.visibility} · {node.mutability}{node.modifiers.length ? ` · modifiers: ${node.modifiers.join(", ")}` : ""}</div>
        <div className="ce-tags">{node.characteristics.map((item) => <span key={item.kind}>{item.kind}</span>)}
          {!!facts?.stateReads.length && <span>state reads</span>}{!!facts?.stateWrites.length && <span>state writes</span>}
          {facts?.tokenTransferLike && <span>token-transfer-like</span>}{facts?.nativeValueTransfer && <span>native value</span>}
          {facts?.lowLevelCalls.map((kind, index) => <span key={`${kind}-${index}`}>{kind}</span>)}</div></div>
      {node.source && <Link className="muted-link mono" href={`/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(node.source.sourceUnitName)}&line=${node.source.startLine}`}>
        {node.source.sourceUnitName}:{node.source.startLine} ↗</Link>}
    </li>)}</ul>
    {shown.length === 0 && <p className="card muted">No functions match these filters.</p>}
    {shown.length > limit && <button className="button secondary-button ce-more" type="button" onClick={() => setLimit((value) => value + 60)}>Show next 60</button>}
    <p className="ce-note">Entry point means public, external, receive or fallback access where the graph proves it. A modifier name alone does not prove authorization.</p>
  </section>;
}
