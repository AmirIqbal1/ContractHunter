"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Background, Controls, MiniMap, ReactFlow, ReactFlowProvider, Handle, Position,
  useReactFlow, type NodeProps } from "@xyflow/react";
import type { ProtocolGraphNode, ProtocolSourceLocation, StaticProtocolGraphArtifact } from "@contracthunter/core";
import { defaultOptions, edgeDetails, findingIds, layoutMap, nodeDetails, relationshipGroups,
  searchMap, visibleModel, type MapDirection, type MapNodeData, type MapOptions, type MapPreset } from "@/lib/protocol-map";

const presets: Array<{ value: MapPreset; label: string }> = [
  { value: "all", label: "All" }, { value: "core", label: "Core protocol" },
  { value: "external", label: "External calls" }, { value: "upgrade", label: "Upgradeability" },
  { value: "findings", label: "Findings" },
];
const relationLabels: Record<string, string> = { calls: "Calls", inheritance: "Inheritance", interfaces: "Interfaces",
  libraries: "Libraries", controls: "Controls", upgrades: "Upgrades", delegation: "Delegatecall",
  external: "External calls" };
const sourceHref = (scanId: string, source: ProtocolSourceLocation) =>
  `/hunts/${encodeURIComponent(scanId)}/source?unit=${encodeURIComponent(source.sourceUnitName)}&line=${source.startLine}`;
function SourceLink({ scanId, source }: { scanId: string; source: ProtocolSourceLocation | null }) {
  if (!source) return <span className="muted">Source location unavailable</span>;
  return <Link className="muted-link mono" href={sourceHref(scanId, source)}>
    {source.sourceUnitName}:{source.startLine}{source.endLine !== source.startLine ? `–${source.endLine}` : ""} ↗
  </Link>;
}
function ProtocolNode({ data }: NodeProps) {
  const item = data as MapNodeData;
  return <div className={`pm-node pm-node-${item.kind} pm-class-${item.classification}${item.selected ? " is-selected" : ""}${item.dimmed ? " is-dimmed" : ""}`}>
    <Handle type="target" position={Position.Left} isConnectable={false} />
    <div className="pm-node-top"><span className="pm-node-kind">{item.kind === "external-actor" ? "UNRESOLVED" : item.kind.toUpperCase()}</span>
      {item.findingCount > 0 && <span className="pm-finding-badge">{item.findingCount} finding{item.findingCount === 1 ? "" : "s"}</span>}</div>
    <strong title={item.label}>{item.label}</strong>
    <div className="pm-node-meta">{item.classification}{item.badges.length ? ` · ${item.badges.join(" · ")}` : ""}</div>
    <Handle type="source" position={Position.Right} isConnectable={false} />
  </div>;
}
const nodeTypes = { protocol: ProtocolNode };
function GraphCanvas({ artifact, options, selectedId, selectedEdgeId, setSelectedId, setSelectedEdgeId,
  focusId, direction }: { artifact: StaticProtocolGraphArtifact; options: MapOptions;
  selectedId: string | null; selectedEdgeId: string | null; setSelectedId: (id: string | null) => void;
  setSelectedEdgeId: (id: string | null) => void; focusId: string | null; direction: MapDirection }) {
  const flow = useReactFlow();
  const view = useMemo(() => layoutMap(visibleModel(artifact, options, focusId)),
    [artifact, options, focusId]);
  const highlighted = useMemo(() => {
    const neighbors = new Set(selectedId ? [selectedId] : []);
    if (selectedId) for (const edge of view.edges) {
      if (direction !== "callers" && edge.source === selectedId) neighbors.add(edge.target);
      if (direction !== "callees" && edge.target === selectedId) neighbors.add(edge.source);
    }
    return { nodes: view.nodes.map((node) => ({ ...node,
      data: { ...node.data, selected: node.id === selectedId, dimmed: !!selectedId && !neighbors.has(node.id) } })),
    edges: view.edges.map((edge) => ({ ...edge,
      style: { ...edge.style, opacity: selectedId && edge.source !== selectedId && edge.target !== selectedId ? 0.22 : 0.8 } })) };
  }, [view, selectedId, direction]);
  useEffect(() => {
    if (!focusId) return;
    const node = view.nodes.find((item) => item.id === focusId);
    if (node) void flow.setCenter(node.position.x + 105, node.position.y + 53, { zoom: 1.1, duration: 250 });
  }, [focusId, flow, view.nodes]);
  const styledEdges = useMemo(() => highlighted.edges.map((edge) => ({ ...edge,
    className: edge.id === selectedEdgeId ? "pm-edge-selected" : undefined })), [highlighted.edges, selectedEdgeId]);
  return <>
    <div className="pm-canvas" aria-label="Protocol relationship graph">
      {view.nodes.length ? <ReactFlow nodes={highlighted.nodes} edges={styledEdges} nodeTypes={nodeTypes}
        fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.1} maxZoom={2} nodesDraggable={false}
        nodesConnectable={false} elementsSelectable nodesFocusable edgesFocusable
        onNodeClick={(_, node) => { setSelectedId(node.id); setSelectedEdgeId(null); }}
        onEdgeClick={(_, edge) => { setSelectedId(null); setSelectedEdgeId(edge.id); }}
        onPaneClick={() => { setSelectedId(null); setSelectedEdgeId(null); }}>
        <Background color="#26323b" gap={24} size={1} /><Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeColor={(node) => node.data.classification === "core" ? "#57e6ad" : "#64748b"} />
      </ReactFlow> : <div className="pm-empty-canvas">No nodes match these filters. Reset filters or choose another view.</div>}
    </div>
    <div className="pm-counts" role="status">Showing {view.nodes.length} of {view.totalNodes} non-function nodes · {view.edges.length} of {view.totalEdges} cross-node relationships
      {view.hiddenFunctionNodes > 0 ? ` · ${view.hiddenFunctionNodes} functions in details` : ""}
      {view.clipped ? " · renderer limit reached; narrow the filters" : ""}</div>
    <div className="pm-text-relationships"><h3>Visible relationships</h3>
      {view.edges.length ? <ul>{view.edges.slice(0, 100).map((edge) => {
        const detail = edgeDetails(artifact, edge.id);
        return detail ? <li key={edge.id}><button type="button" onClick={() => { setSelectedId(null); setSelectedEdgeId(edge.id); }}>
          {detail.from.name} → {detail.to.name} · {detail.edge.kind}</button></li> : null;
      })}</ul> : <p className="muted">No relationships in the current view.</p>}
      {view.edges.length > 100 && <p className="muted">Showing the first 100 relationships here; use the canvas and filters for the rest.</p>}
    </div>
  </>;
}
function NodePanel({ artifact, scanId, nodeId, onSelect }: { artifact: StaticProtocolGraphArtifact;
  scanId: string; nodeId: string; onSelect: (id: string) => void }) {
  const detail = nodeDetails(artifact, nodeId);
  if (!detail) return null;
  const { node, callers, callees, functions, related, unresolved, findingIds: findings } = detail;
  const entryPoints = functions.filter((item) => item.kind === "function" && item.entryPoint === "yes");
  const relationshipList = (items: ProtocolGraphNode[]) => items.length ? <ul>{items.slice(0, 50).map((item) =>
    <li key={item.id}><button type="button" onClick={() => onSelect(item.id)}>{item.name} <small>{item.kind}</small></button></li>)}</ul> : <p className="muted">None recorded in this graph.</p>;
  return <div className="pm-detail-content">
    <div className="pm-detail-eyebrow">{node.kind} · {"repositoryClassification" in node ? node.repositoryClassification.effective : "structural concept"}</div>
    <h2>{node.name}</h2><SourceLink scanId={scanId} source={node.source} />
    {(node.kind === "contract" || node.kind === "interface" || node.kind === "library") &&
      <p><Link className="muted-link" href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(node.id)}`}>
        Open Contract Explorer →</Link></p>}
    {"abstract" in node && node.abstract && <p className="pm-note">Abstract contract</p>}
    <dl className="pm-metrics"><div><dt>Callers</dt><dd>{callers.length}</dd></div><div><dt>Callees</dt><dd>{callees.length}</dd></div>
      <div><dt>Entry points</dt><dd>{entryPoints.length}</dd></div><div><dt>Findings</dt><dd>{findings.length}</dd></div>
      <div><dt>Relationships</dt><dd>{related.length}</dd></div><div><dt>Unresolved</dt><dd>{unresolved.length}</dd></div></dl>
    {node.characteristics.length > 0 && <section><h3>Security characteristics</h3><div className="pm-tags">{node.characteristics.map((item) =>
      <span key={item.kind}>{item.kind}</span>)}</div></section>}
    {findings.length > 0 && <section><h3>Exact finding references</h3><ul>{findings.slice(0, 40).map((id) =>
      <li key={id}><Link href={`/findings/${encodeURIComponent(id)}`}>Open finding {id.slice(0, 8)} ↗</Link></li>)}</ul></section>}
    <section><h3>Callers and controls</h3>{relationshipList(callers)}</section>
    <section><h3>Callees and dependencies</h3>{relationshipList(callees)}</section>
    {unresolved.length > 0 && <section><h3>Unresolved calls</h3><p className="muted">The target could not be statically resolved.</p>
      <ul>{unresolved.slice(0, 40).map((item, index) => <li key={`${item.callerFunctionId}-${index}`}>
        {item.kind} · {item.reason} · <SourceLink scanId={scanId} source={item.source} /></li>)}</ul></section>}
    {functions.length > 0 && <section><h3>Functions</h3><ul className="pm-function-list">{functions.slice(0, 100).map((item) =>
      item.kind === "function" ? <li key={item.id}><div><strong className="mono">{item.signature}</strong>
        <span className="pm-function-meta">{item.entryPoint === "yes" ? "ENTRY" : item.entryPoint === "no" ? "NOT ENTRY" : "UNKNOWN ENTRY"} · {item.visibility} · {item.mutability}
          {item.characteristics.length ? ` · ${item.characteristics.map((trait) => trait.kind).join(", ")}` : ""}
          {findingIds(artifact, item.id).length ? ` · ${findingIds(artifact, item.id).length} findings` : ""}</span></div>
        <SourceLink scanId={scanId} source={item.source} /></li> : null)}</ul>
      {functions.length > 100 && <p className="muted">First 100 functions shown.</p>}</section>}
    <section><h3>Provenance</h3><ul>{node.evidence.map((item, index) => <li key={index}>{item.origin} · {item.producerVersion}</li>)}</ul></section>
  </div>;
}
function EdgePanel({ artifact, scanId, edgeId }: { artifact: StaticProtocolGraphArtifact; scanId: string; edgeId: string }) {
  const detail = edgeDetails(artifact, edgeId);
  if (!detail) return null;
  const { edge, from, to, fromFunction, toFunction } = detail;
  return <div className="pm-detail-content"><div className="pm-detail-eyebrow">Relationship · {edge.kind}</div>
    <h2>{from.name} → {to.name}</h2><p>{edge.reasons.join(", ")}</p>
    {(fromFunction || toFunction) && <p className="mono">{fromFunction?.kind === "function" ? fromFunction.signature : from.name} → {toFunction?.kind === "function" ? toFunction.signature : to.name}</p>}
    <SourceLink scanId={scanId} source={edge.source} />
    <section><h3>Source-backed evidence</h3><ul>{edge.evidence.map((item, index) => <li key={index}>
      {item.origin} · {item.producerVersion}{item.referenceId ? ` · ${item.referenceId}` : ""}
      {item.source && <> · <SourceLink scanId={scanId} source={item.source} /></>}</li>)}</ul></section>
    <p className="pm-note">This is a {edge.origin} relationship. A call or control edge does not establish a vulnerability.</p>
  </div>;
}

export function ProtocolMap({ artifact, scanId, initialSelectedId = null }: { artifact: StaticProtocolGraphArtifact;
  scanId: string; initialSelectedId?: string | null }) {
  const [options, setOptions] = useState<MapOptions>(() => initialSelectedId ?
    { ...defaultOptions(artifact), preset: "all", hideInterfaces: false, hideLibraries: false, hideDependencies: false } :
    defaultOptions(artifact));
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(initialSelectedId);
  const [direction, setDirection] = useState<MapDirection>("both");
  const matches = useMemo(() => searchMap(artifact, query), [artifact, query]);
  const choose = (id: string) => { setOptions({ ...defaultOptions(artifact), preset: "all", hideInterfaces: false,
    hideLibraries: false, hideDependencies: false }); setSelectedId(id); setSelectedEdgeId(null); setFocusId(id); };
  const reset = () => { setOptions(defaultOptions(artifact)); setSelectedId(null); setSelectedEdgeId(null); setQuery(""); setFocusId(null); };
  const toggle = (key: "hideInterfaces" | "hideLibraries" | "hideDependencies" | "findingOnly") =>
    setOptions((old) => ({ ...old, [key]: !old[key] }));
  const byId = useMemo(() => new Map(artifact.graph.nodes.map((node) => [node.id, node])), [artifact]);
  const selectNode = (id: string | null) => { setSelectedId(id); setSelectedEdgeId(null); };
  return <div className="pm-workspace">
    <div className="pm-main">
      <div className="pm-toolbar" aria-label="Protocol Map controls">
        <label>View <select value={options.preset} onChange={(event) => setOptions((old) => ({ ...old, preset: event.target.value as MapPreset }))}>
          {presets.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
        <label>Search contracts, functions, source <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Vault, withdraw(), src/Vault.sol" /></label>
        <button type="button" onClick={reset}>Reset filters</button>
      </div>
      {query.trim() && <div className="pm-search-results" role="listbox" aria-label="Protocol Map search results">
        {matches.length ? matches.map((item) => <button type="button" role="option" aria-selected={selectedId === item.id} key={item.id} onClick={() => choose(item.id)}>
          {item.name} <small>{item.source?.sourceUnitName ?? item.kind}</small></button>) : <span>No matching graph identity.</span>}
      </div>}
      <div className="pm-filter-row">
        <label><input type="checkbox" checked={options.hideInterfaces} onChange={() => toggle("hideInterfaces")} /> Hide interfaces</label>
        <label><input type="checkbox" checked={options.hideLibraries} onChange={() => toggle("hideLibraries")} /> Hide libraries</label>
        <label><input type="checkbox" checked={options.hideDependencies} onChange={() => toggle("hideDependencies")} /> Hide dependencies</label>
        <label><input type="checkbox" checked={options.findingOnly} onChange={() => toggle("findingOnly")} /> Findings only</label>
      </div>
      <details className="pm-rel-filters"><summary>Relationship filters</summary><div className="pm-filter-row">
        {Object.entries(relationshipGroups).map(([name, kinds]) => <label key={name}><input type="checkbox"
          checked={kinds.every((kind) => options.relationshipKinds.has(kind))}
          onChange={() => setOptions((old) => {
            const next = new Set(old.relationshipKinds);
            for (const kind of kinds) if (kinds.every((item) => next.has(item))) next.delete(kind); else next.add(kind);
            return { ...old, relationshipKinds: next };
          })} /> {relationLabels[name]}</label>)}</div></details>
      {artifact.unresolved.length > 0 || artifact.graph.warnings.length > 0 ? <p className="pm-warning">
        {artifact.unresolved.length} relationships unresolved · {artifact.graph.warnings.length} extraction warnings. Missing targets are not inferred.
      </p> : null}
      <div className="pm-legend"><span>▰ Core</span><span>▱ Periphery</span><span>◇ Interface</span><span>▣ Library</span>
        <span>⬡ Proxy</span><span>◌ Unresolved</span><span>● Findings</span></div>
      <ReactFlowProvider><GraphCanvas artifact={artifact} options={options} selectedId={selectedId}
        selectedEdgeId={selectedEdgeId} setSelectedId={selectNode} setSelectedEdgeId={setSelectedEdgeId}
        focusId={focusId} direction={direction} /></ReactFlowProvider>
    </div>
    <aside className="pm-panel" aria-label="Selected graph details">
      <div className="pm-panel-head"><strong>Research details</strong><span>Static facts · {artifact.graph.schema}</span></div>
      {selectedId && byId.has(selectedId) ? <><div className="pm-direction">
        {(["both", "callers", "callees"] as const).map((value) => <button type="button" key={value}
          aria-pressed={direction === value} onClick={() => setDirection(value)}>{value === "both" ? "Neighborhood" : value === "callers" ? "Callers" : "Callees"}</button>)}</div>
        <NodePanel artifact={artifact} scanId={scanId} nodeId={selectedId} onSelect={choose} /></> :
        selectedEdgeId ? <EdgePanel artifact={artifact} scanId={scanId} edgeId={selectedEdgeId} /> :
        <div className="pm-placeholder"><h2>Select a contract or relationship</h2>
          <p>Explore callers, callees, entry points, findings and exact source locations. Search also finds function signatures.</p>
          <p>Entry point means a public or external function, including receive and fallback where present.</p>
          <p><strong>Delegatecall</strong> runs another contract&apos;s code using the caller&apos;s storage.</p></div>}
    </aside>
  </div>;
}
