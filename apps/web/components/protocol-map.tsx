"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Background, Controls, MiniMap, ReactFlow, ReactFlowProvider, Handle, Position,
  useReactFlow, type NodeProps } from "@xyflow/react";
import type { ProtocolGraphNode, ProtocolSourceLocation, SecurityViewResult, StaticProtocolGraphArtifact } from "@contracthunter/core";
import { defaultOptions, edgeDetails, findingIds, layoutMap, nodeDetails, relationshipGroups,
  mapOwner, searchMap, visibleModel, type MapDirection, type MapNodeData, type MapOptions, type MapPreset } from "@/lib/protocol-map";
import { projectionNodeFacts, projectionOwnerIds, reasonHelp, securityMapViews,
  type SecurityMapView } from "@/lib/security-view-map";

const presets: Array<{ value: MapPreset; label: string }> = [
  { value: "all", label: "All" }, { value: "core", label: "Core protocol" },
  { value: "external", label: "External calls" }, { value: "upgrade", label: "Upgradeability" },
  { value: "findings", label: "Findings" },
];
const relationLabels: Record<string, string> = { calls: "Calls", inheritance: "Inheritance", interfaces: "Interfaces",
  libraries: "Libraries", controls: "Controls", upgrades: "Upgrades", delegation: "Delegatecall",
  external: "External calls" };
const viewLegend: Record<SecurityMapView, string[]> = {
  overview: ["▰ Core", "▱ Periphery", "◇ Interface", "▣ Library", "⬡ Proxy", "◌ Unresolved", "● Findings"],
  "money-flow": ["Token transfer-like", "Native value", "CALL edge is not asset direction", "Direction may be unresolved"],
  permissions: ["⬡ Proven role", "Controls specific functions", "No security verdict"],
  "oracle-flow": ["Oracle-like evidence", "Consumer relationship", "No inferred price impact"],
  "external-calls": ["High-level external call", "Low-level call", "STATICCALL", "DELEGATECALL", "Target unresolved"],
  upgradeability: ["⬡ Proven proxy", "Implementation", "Upgrade authority where proven"],
  "attack-surface": ["External entry point", "Payable", "Sensitive static operation", "No vulnerability verdict"],
  findings: ["● Exact finding attachment", "Open finding for investigation"],
};
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
  focusId, direction, projection }: { artifact: StaticProtocolGraphArtifact; options: MapOptions; projection: SecurityViewResult | null;
  selectedId: string | null; selectedEdgeId: string | null; setSelectedId: (id: string | null) => void;
  setSelectedEdgeId: (id: string | null) => void; focusId: string | null; direction: MapDirection }) {
  const flow = useReactFlow();
  const view = useMemo(() => layoutMap(visibleModel(artifact, options, focusId, direction, projection)),
    [artifact, options, focusId, direction, projection]);
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
  const projectionId = projection?.id;
  useEffect(() => { if (projectionId) void flow.fitView({ padding: 0.12, duration: 200 }); }, [projectionId, flow]);
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
        <Link className="muted-link" href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(node.id)}/functions/${encodeURIComponent(item.id)}`}>Open Function Explorer →</Link> · <SourceLink scanId={scanId} source={item.source} /></li> : null)}</ul>
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

function ReasonList({ reasons, scanId, researcher }: { reasons: SecurityViewResult["nodes"][number]["reasons"];
  scanId: string; researcher: boolean }) {
  return <ul className="pm-reasons">{reasons.slice(0, 8).map((reason, index) => <li key={`${reason.code}-${reason.sourceId}-${index}`}>
    <strong>{reason.code.replaceAll("-", " ")}</strong>
    <p>{reasonHelp[reason.explanationKey] ?? "Included by a source-backed static graph fact."}</p>
    <SourceLink scanId={scanId} source={reason.source} />
    {researcher && <p className="mono">{reason.sourceKind} · {reason.sourceId} · {reason.evidence.map((item) => `${item.origin} ${item.producerVersion}`).join(", ")}</p>}
  </li>)}</ul>;
}
function ProjectionDetails({ artifact, projection, scanId, selectedId, selectedEdgeId, researcher }: {
  artifact: StaticProtocolGraphArtifact; projection: SecurityViewResult; scanId: string;
  selectedId: string | null; selectedEdgeId: string | null; researcher: boolean }) {
  const nodeFacts = selectedId ? projectionNodeFacts(artifact, projection, selectedId) : [];
  const edgeFact = projection.edges.find((item) => item.id === selectedEdgeId);
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const annotations = projection.annotations.filter((item) => {
    const node = byId.get(item.nodeId);
    return (selectedId && node && mapOwner(node, byId).id === selectedId) || (selectedEdgeId && item.graphEdgeId === selectedEdgeId);
  }).slice(0, 50);
  const reasons = edgeFact?.reasons ?? nodeFacts.flatMap((item) => item.reasons).slice(0, 16);
  const controlledFunctions = selectedId ? projection.edges.flatMap((item) => {
    const edge = artifact.graph.edges.find((candidate) => candidate.id === item.id);
    if (!edge || edge.kind !== "controls" || edge.from !== selectedId) return [];
    const target = byId.get(edge.to);
    return target?.kind === "function" ? [target] : [];
  }).slice(0, 50) : [];
  if (!selectedId && !selectedEdgeId) return null;
  return <section className="pm-projection-details"><h3>Why this is shown</h3>
    {researcher && <p className="mono">Canonical graph ID: {selectedEdgeId ?? selectedId}</p>}
    {reasons.length ? <ReasonList reasons={reasons} scanId={scanId} researcher={researcher} /> : <p className="muted">No inclusion reason for this selection.</p>}
    {edgeFact && <p>Call type: {edgeFact.callType} · Target: {edgeFact.targetContext}</p>}
    {nodeFacts.some((item) => item.node.kind === "function") && <section><h3>Included functions</h3><ul>{nodeFacts.filter((item) => item.node.kind === "function").slice(0, 50).map(({ node }) =>
      node.kind === "function" ? <li key={node.id}><Link href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(node.contractId)}/functions/${encodeURIComponent(node.id)}`}>
        {node.signature} → Function Explorer</Link></li> : null)}</ul></section>}
    {controlledFunctions.length > 0 && <section><h3>Affected functions</h3><ul>{controlledFunctions.map((node) =>
      <li key={node.id}><Link href={`/hunts/${encodeURIComponent(scanId)}/contracts/${encodeURIComponent(node.contractId)}/functions/${encodeURIComponent(node.id)}`}>
        {node.signature} → Function Explorer</Link></li>)}</ul></section>}
    {annotations.length > 0 && <section><h3>Static annotations</h3><ul>{annotations.map((item) => <li key={item.id}>
      <strong>{item.kind.replaceAll("-", " ")}</strong> · {item.targetStatus === "unresolved" ? "Target unresolved" : item.targetStatus}
      {item.kind === "token-transfer-like" || item.kind === "native-value-transfer" ? ` · Direction ${item.assetDirection}` : ""}
      {item.findingId && <Link href={`/findings/${encodeURIComponent(item.findingId)}`}>Open finding →</Link>}
      {item.source && <> · <SourceLink scanId={scanId} source={item.source} /></>}
    </li>)}</ul></section>}
    {projection.viewType === "findings" && <section><h3>Finding references</h3><ul>{projection.findingMetadata.filter((finding) =>
      annotations.some((item) => item.findingId === finding.id)).map((finding) => <li key={finding.id}>
      <Link href={`/findings/${encodeURIComponent(finding.id)}`}>{finding.title} · {finding.source} · {finding.status}</Link></li>)}</ul></section>}
  </section>;
}

export function ProtocolMap({ artifact, scanId, initialSelectedId = null, initialView = "overview" }: { artifact: StaticProtocolGraphArtifact;
  scanId: string; initialSelectedId?: string | null; initialView?: SecurityMapView }) {
  const [securityView, setSecurityView] = useState<SecurityMapView>(initialView);
  const [projectionCache, setProjectionCache] = useState<Partial<Record<SecurityMapView, SecurityViewResult>>>({});
  const [viewError, setViewError] = useState(false);
  const [researcher, setResearcher] = useState(false);
  const [focusOnly, setFocusOnly] = useState(false);
  const [options, setOptions] = useState<MapOptions>(() => initialSelectedId ?
    { ...defaultOptions(artifact), preset: "all", hideInterfaces: false, hideLibraries: false, hideDependencies: false } :
    defaultOptions(artifact));
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(initialSelectedId);
  const [direction, setDirection] = useState<MapDirection>("both");
  const projection = securityView === "overview" ? null : projectionCache[securityView] ?? null;
  const ownerIds = useMemo(() => projection ? projectionOwnerIds(artifact, projection) : null, [artifact, projection]);
  const matches = useMemo(() => searchMap(artifact, query).filter((item) => !ownerIds || ownerIds.has(item.id)),
    [artifact, query, ownerIds]);
  useEffect(() => {
    if (securityView === "overview" || projectionCache[securityView]) return;
    const controller = new AbortController();
    fetch(`/api/scans/${encodeURIComponent(scanId)}/protocol-graph/security-views/${securityView}`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw Error("view_unavailable");
        const result = await response.json() as SecurityViewResult;
        if (result.viewType !== securityView || result.scanId !== scanId ||
          result.protocolGraphId !== artifact.graph.id || result.graphContentSha256 !== artifact.contentSha256 ||
          !Array.isArray(result.nodes) || !Array.isArray(result.edges)) throw Error("view_mismatch");
        const owners = projectionOwnerIds(artifact, result);
        setSelectedId((id) => id && owners.has(id) ? id : null);
        setSelectedEdgeId((id) => id && result.edges.some((item) => item.id === id) ? id : null);
        setProjectionCache((old) => ({ ...old, [securityView]: result })); setViewError(false);
      }).catch((error: unknown) => { if (error instanceof Error && error.name === "AbortError") return; setViewError(true); });
    return () => controller.abort();
  }, [artifact, projectionCache, scanId, securityView]);
  const visibleSelectedId = securityView === "overview" || selectedId && ownerIds?.has(selectedId) ? selectedId : null;
  const visibleSelectedEdgeId = securityView === "overview" || selectedEdgeId && projection?.edges.some((item) => item.id === selectedEdgeId) ? selectedEdgeId : null;
  const changeView = (next: SecurityMapView) => {
    setSecurityView(next); setViewError(false); setFocusOnly(false); setFocusId(null);
    const cached = projectionCache[next];
    if (cached) {
      const owners = projectionOwnerIds(artifact, cached);
      setSelectedId((id) => id && owners.has(id) ? id : null);
      setSelectedEdgeId((id) => id && cached.edges.some((item) => item.id === id) ? id : null);
    }
    setOptions({ ...defaultOptions(artifact), preset: "all", hideInterfaces: false, hideLibraries: false,
      hideDependencies: false, findingOnly: false });
    const url = new URL(window.location.href);
    if (next === "overview") url.searchParams.delete("view"); else url.searchParams.set("view", next);
    window.history.replaceState(null, "", url.toString());
  };
  const choose = (id: string) => { setOptions({ ...defaultOptions(artifact), preset: "all", hideInterfaces: false,
    hideLibraries: false, hideDependencies: false }); setSelectedId(id); setSelectedEdgeId(null); setFocusId(id); };
  const reset = () => { setOptions(defaultOptions(artifact)); setSelectedId(null); setSelectedEdgeId(null); setQuery(""); setFocusId(null); };
  const toggle = (key: "hideInterfaces" | "hideLibraries" | "hideDependencies" | "findingOnly") =>
    setOptions((old) => ({ ...old, [key]: !old[key] }));
  const byId = useMemo(() => new Map(artifact.graph.nodes.map((node) => [node.id, node])), [artifact]);
  const selectNode = (id: string | null) => { setSelectedId(id); setSelectedEdgeId(null); };
  const displayProjection = useMemo(() => {
    if (!projection || !focusOnly || !visibleSelectedId) return projection;
    const neighbors = new Set([visibleSelectedId]);
    const focusedEdgeIds = new Set<string>();
    const graphEdges = new Map(artifact.graph.edges.map((edge) => [edge.id, edge]));
    for (const item of projection.edges) {
      const edge = graphEdges.get(item.id);
      if (!edge) continue;
      const from = byId.get(edge.from), to = byId.get(edge.to);
      if (!from || !to) continue;
      const fromOwner = mapOwner(from, byId).id, toOwner = mapOwner(to, byId).id;
      if (fromOwner === visibleSelectedId || toOwner === visibleSelectedId) {
        focusedEdgeIds.add(item.id); neighbors.add(fromOwner); neighbors.add(toOwner);
      }
    }
    return {
    ...projection,
    nodes: projection.nodes.filter((item) => {
      const node = byId.get(item.id);
      return !!node && neighbors.has(mapOwner(node, byId).id);
    }),
    edges: projection.edges.filter((item) => focusedEdgeIds.has(item.id)),
    };
  }, [projection, focusOnly, visibleSelectedId, artifact, byId]);
  return <div className="pm-workspace">
    <div className="pm-main">
      <nav className="pm-view-selector" aria-label="Security views"><button type="button" aria-pressed={securityView === "overview"}
        onClick={() => changeView("overview")}>Overview</button>{securityMapViews.map((item) => <button type="button" key={item.value}
          aria-pressed={securityView === item.value} onClick={() => changeView(item.value)}>{item.label}</button>)}</nav>
      {securityView !== "overview" && !projection && !viewError && <p className="pm-warning" role="status">Loading {securityView.replaceAll("-", " ")} view…</p>}
      {viewError && <p className="pm-warning" role="alert">This Security View could not be loaded. Overview remains available.
        <button type="button" onClick={() => changeView("overview")}>Open Overview</button></p>}
      {projection && <><div className="pm-view-summary"><strong>{securityMapViews.find((item) => item.value === securityView)?.label} · static view</strong>
        <span>{projection.summary.nodeCount} graph identities · {projection.summary.edgeCount} relationships · {projection.summary.annotationCount} annotations</span>
        {projection.summary.metrics.filter((item) => item.value > 0).map((item) => <span key={item.key}>{item.key.replace(/([A-Z])/g, " $1").toLowerCase()}: {item.value}</span>)}</div>
        {securityView === "money-flow" && <p className="pm-warning">STATIC MONEY FLOW · Based on static code structure. Actual runtime asset movement may differ. Direction unresolved where evidence does not prove it.</p>}
        {projection.warnings.length > 0 && <details className="pm-view-warnings"><summary>{projection.warnings.reduce((sum, item) => sum + item.count, 0)} view limitations or unresolved facts</summary>
          <ul>{projection.warnings.map((item) => <li key={item.code}>{item.code.replaceAll("-", " ")}: {item.count}</li>)}</ul></details>}
        {projection.nodes.length === 0 && projection.annotations.length === 0 && <p className="pm-empty-view">No deterministic {securityView.replaceAll("-", " ")} relationships were identified for this scan. This does not prove that none exist.</p>}
      </>}
      <div className="pm-toolbar" aria-label="Protocol Map controls">
        {securityView === "overview" && <label>Overview preset <select value={options.preset} onChange={(event) => setOptions((old) => ({ ...old, preset: event.target.value as MapPreset }))}>
          {presets.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>}
        <label>Search contracts, functions, source <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Vault, withdraw(), src/Vault.sol" /></label>
        <button type="button" aria-pressed={focusOnly} disabled={!visibleSelectedId || !projection} onClick={() => setFocusOnly((old) => !old)}>Focus on selected</button>
        <button type="button" aria-pressed={researcher} onClick={() => setResearcher((old) => !old)}>{researcher ? "Researcher" : "Beginner"} details</button>
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
      {securityView === "overview" && (artifact.unresolved.length > 0 || artifact.graph.warnings.length > 0) ? <p className="pm-warning">
        {artifact.unresolved.length} relationships unresolved · {artifact.graph.warnings.length} extraction warnings. Missing targets are not inferred.
      </p> : null}
      <div className="pm-legend" aria-label={`${securityView} legend`}>{viewLegend[securityView].map((item) => <span key={item}>{item}</span>)}</div>
      {(securityView === "overview" || projection) && !viewError && <ReactFlowProvider><GraphCanvas artifact={artifact} options={options} projection={displayProjection} selectedId={visibleSelectedId}
        selectedEdgeId={visibleSelectedEdgeId} setSelectedId={selectNode} setSelectedEdgeId={setSelectedEdgeId}
        focusId={focusId} direction={direction} /></ReactFlowProvider>}
    </div>
    <aside className="pm-panel" aria-label="Selected graph details">
      <div className="pm-panel-head"><strong>Research details</strong><span>Static facts · {artifact.graph.schema}</span></div>
      {visibleSelectedId && byId.has(visibleSelectedId) ? <><div className="pm-direction">
        {(["both", "callers", "callees"] as const).map((value) => <button type="button" key={value}
          aria-pressed={direction === value} onClick={() => setDirection(value)}>{value === "both" ? "Neighborhood" : value === "callers" ? "Callers" : "Callees"}</button>)}</div>
        <NodePanel artifact={artifact} scanId={scanId} nodeId={visibleSelectedId} onSelect={choose} /></> :
        visibleSelectedEdgeId ? <EdgePanel artifact={artifact} scanId={scanId} edgeId={visibleSelectedEdgeId} /> :
        <div className="pm-placeholder"><h2>Select a contract or relationship</h2>
          <p>Explore callers, callees, entry points, findings and exact source locations. Search also finds function signatures.</p>
          <p>Entry point means a public or external function, including receive and fallback where present.</p>
          <p><strong>Delegatecall</strong> runs another contract&apos;s code using the caller&apos;s storage.</p></div>}
      {projection && <ProjectionDetails artifact={artifact} projection={projection} scanId={scanId}
        selectedId={visibleSelectedId}
        selectedEdgeId={visibleSelectedEdgeId}
        researcher={researcher} />}
    </aside>
  </div>;
}
