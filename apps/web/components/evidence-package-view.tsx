"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { type EvidencePackage } from "@contracthunter/core";

export function EvidencePackageView({ value, persisted, history = [], reports = [] }: { value: EvidencePackage; persisted: boolean;
  history?: Array<{ id: string; status: string; createdAt: number }>;
  reports?: Array<{ id: string; status: string; createdAt: number }> }) {
  const router = useRouter();
  const [mode, setMode] = useState<"beginner" | "researcher">("beginner");
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const api = `/api/scans/${encodeURIComponent(value.scanId)}/impact/evidence-packages`;
  const here = `/hunts/${encodeURIComponent(value.scanId)}/evidence-packages/${encodeURIComponent(value.packageId)}`;
  const chosen = value.artifacts.find((item) => `${item.type}:${item.id}` === selected);
  const scenario = value.artifacts.find((item) => item.type === "reviewed-scenario")?.data as
    { scenarioId?: string } | undefined;
  const replay = value.artifacts.find((item) => item.type === "replay")?.data as
    { plan?: { planId?: string }; run?: { id?: string } } | undefined;
  const source = chosen?.type === "source" ? chosen.data as { sourceUnit?: string; startLine?: number } : null;
  const graph = value.artifacts.find((item) => item.type === "protocol-graph-subset")?.data as
    { nodes?: Array<{ id: string; kind: string; name: string; contractId?: string }> } | undefined;
  async function act(action: "create" | "finalize") {
    setBusy(true); setError("");
    try {
      const response = await fetch(action === "create" ? api : `${api}/${encodeURIComponent(value.packageId)}/finalize`,
        { method: "POST", headers: { "content-type": "application/json" }, body: action === "create" ?
          JSON.stringify({ subjectType: value.subject.type, subjectId: value.subject.id,
            ...value.selection }) : "{}" });
      if (!response.ok) throw Error(action === "create" ? "Package draft could not be created." :
        "Evidence changed or finalization was refused.");
      const result = await response.json() as { packageId: string };
      router.push(action === "create" ?
        `/hunts/${encodeURIComponent(value.scanId)}/evidence-packages/${encodeURIComponent(result.packageId)}` : here);
      router.refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Package action failed."); }
    finally { setBusy(false); }
  }
  async function createReport() {
    setBusy(true); setError("");
    try {
      const response = await fetch(`${api}/${encodeURIComponent(value.packageId)}/reports`,
        { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      if (!response.ok) throw Error("Report draft could not be created from this package.");
      const result = await response.json() as { reportId: string };
      router.push(`${here}/reports/${encodeURIComponent(result.reportId)}`);
      router.refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Report action failed."); }
    finally { setBusy(false); }
  }
  return <div className="af-view"><header className="page-head"><div>
    <div className="eyebrow">{value.status === "finalized" ? "FINALIZED EVIDENCE PACKAGE" : "DRAFT EVIDENCE PACKAGE"}</div>
    <h1>Evidence Package</h1>
    <p className="subhead">Frozen, auditable evidence for one exact investigation or local reproduction.</p>
  </div></header>
    <nav className="ip-actions"><Link href={`/hunts/${encodeURIComponent(value.scanId)}`}>Back to hunt</Link>
      {value.selection.executionId && <Link href={`/hunts/${encodeURIComponent(value.scanId)}/impact/executions/${encodeURIComponent(value.selection.executionId)}`}>Observed Execution</Link>}
      {value.selection.executionId && <Link href={`/hunts/${encodeURIComponent(value.scanId)}/impact/executions/${encodeURIComponent(value.selection.executionId)}/assets`}>Asset Flow</Link>}
      {value.selection.executionId && scenario?.scenarioId && <Link href={`/hunts/${encodeURIComponent(value.scanId)}/impact/executions/${encodeURIComponent(value.selection.executionId)}/assets/scenarios/${encodeURIComponent(scenario.scenarioId)}`}>Reviewed Scenario</Link>}
      {value.selection.executionId && scenario?.scenarioId && replay?.plan?.planId && replay.run?.id && <Link href={`/hunts/${encodeURIComponent(value.scanId)}/impact/executions/${encodeURIComponent(value.selection.executionId)}/assets/scenarios/${encodeURIComponent(scenario.scenarioId)}/replay/${encodeURIComponent(replay.plan.planId)}/runs/${encodeURIComponent(replay.run.id)}`}>Replay Result</Link>}
      <Link href={`/hunts/${encodeURIComponent(value.scanId)}/investigation-paths/${value.subject.type}/${encodeURIComponent(value.subject.id)}`}>Static Investigation Path</Link>
      {value.status === "finalized" && <a href={`${api}/${encodeURIComponent(value.packageId)}/download`}>Download JSON</a>}</nav>
    <div className="af-mode" role="group" aria-label="Presentation mode">{(["beginner", "researcher"] as const).map((item) =>
      <button key={item} type="button" aria-pressed={mode === item} onClick={() => setMode(item)}>{item === "beginner" ? "Beginner" : "Researcher"}</button>)}</div>
    {mode === "beginner" && <p>Evidence Package: a frozen bundle of source, local reproduction evidence and analysis. Manifest: the list and hashes of included evidence. Content hash: a fingerprint that detects changed package content.</p>}
    {error && <p role="alert" className="af-warning">{error}</p>}
    {history.length > 0 && <section className="card"><h2>Earlier packages for this subject</h2><ul>{history.map((item) =>
      <li key={item.id}><Link href={`/hunts/${encodeURIComponent(value.scanId)}/evidence-packages/${encodeURIComponent(item.id)}`}>{item.status.toUpperCase()} · {new Date(item.createdAt).toISOString()} · {item.id}</Link></li>)}</ul></section>}
    {value.status === "finalized" && <section className="card"><h2>Bug-bounty reports</h2>
      <p>Draft and finalized reports remain bound to this exact package content and manifest.</p>
      <button type="button" disabled={busy} onClick={createReport}>Create Bug-Bounty Report draft</button>
      {reports.length > 0 && <ul>{reports.map((item) => <li key={item.id}>
        <Link href={`${here}/reports/${encodeURIComponent(item.id)}`}>{item.status.toUpperCase()} · {new Date(item.createdAt).toISOString()} · {item.id}</Link>
      </li>)}</ul>}</section>}
    <section className="card"><h2>{value.status === "finalized" ? "Finalized evidence" : "Package preview"}</h2>
      <dl className="io-grid"><div><dt>Subject</dt><dd>{value.subject.type} · {value.subject.title} · {value.subject.status}</dd></div>
        <div><dt>Capability</dt><dd>{value.completeness}</dd></div>
        <div><dt>Included artifacts</dt><dd>{value.artifacts.length}</dd></div>
        <div><dt>Created</dt><dd>{persisted ? new Date(value.createdAt).toISOString() : "Preview only"}</dd></div>
        <div><dt>Finalized</dt><dd>{value.finalizedAt ? new Date(value.finalizedAt).toISOString() : "Not finalized"}</dd></div>
        {mode === "researcher" && <><div><dt>Package ID</dt><dd className="mono">{persisted ? value.packageId : "Assigned when draft is created"}</dd></div>
          <div><dt>Schema / ruleset</dt><dd className="mono">{value.schema} · {value.rulesetVersion}</dd></div>
          <div><dt>Manifest hash</dt><dd className="mono">{value.manifestHash}</dd></div>
          <div><dt>Package content hash</dt><dd className="mono">{value.contentHash}</dd></div></>}</dl>
      {value.localExecutionStatement && <p role="note">{value.localExecutionStatement}</p>}
      {value.status === "draft" && <><p>This freezes the selected evidence references, manifest, provenance and hashes. Future evidence changes require a new package.</p>
        <button type="button" disabled={busy} onClick={() => act(persisted ? "finalize" : "create")}>{persisted ? "Finalize Evidence Package" : "Create Evidence Package draft"}</button></>}
    </section>
    <section className="card"><h2>Capabilities and inclusion</h2><p>Required integrity evidence is retained for any dynamic package. Static context is optional when unavailable. Unavailable evidence is never shown as an empty success.</p>
      <div className="af-table-wrap"><table><thead><tr><th>Evidence</th><th>State</th><th>Policy</th></tr></thead><tbody>
        {Object.entries(value.capabilities).map(([type, status]) => <tr key={type}><td>{type}</td><td>{status.toUpperCase()}</td><td>{["reviewed-poc", "fork-identity", "execution", "trace", "state"].includes(type) && value.selection.executionId ? "Required dynamic integrity" : "Context / selected evidence"}</td></tr>)}
      </tbody></table></div></section>
    <section className="card"><h2>Evidence index / manifest</h2><div className="af-table-wrap"><table><thead><tr><th>Type</th><th>ID</th><th>Version</th><th>Status</th><th>Hash</th><th>Provenance</th><th>Details</th></tr></thead><tbody>
      {value.manifest.map((item) => <tr key={`${item.type}:${item.id}`}><td>{item.type}</td><td className="mono">{item.id}</td><td>{item.schemaVersion}</td><td>{item.status.toUpperCase()}</td><td className="mono">{mode === "researcher" ? item.contentHash : `${item.contentHash.slice(0, 18)}…`}</td><td className="mono">{item.provenance.join(", ") || "Root"}</td><td><button type="button" onClick={() => setSelected(`${item.type}:${item.id}`)}>View Evidence</button></td></tr>)}
    </tbody></table></div>
      {chosen && <aside className="io-detail"><h3>{chosen.type} · {chosen.id}</h3>
        <p>Source content hash: <span className="mono">{chosen.sourceContentHash ?? "Unavailable"}</span></p>
        {source?.sourceUnit && <p><Link href={`/hunts/${encodeURIComponent(value.scanId)}/source?unit=${encodeURIComponent(source.sourceUnit)}&line=${source.startLine ?? 1}`}>Open Source Explorer</Link> · The frozen excerpt below remains the package authority.</p>}
        <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: "28rem", overflowY: "auto" }}>{JSON.stringify(chosen.data, null, 2)}</pre></aside>}
    </section>
    {graph?.nodes?.length ? <section className="card"><h2>Canonical static context links</h2><ul>{graph.nodes.slice(0, 32).map((node) => <li key={node.id}>{node.kind} · {node.name} · <Link href={`/hunts/${encodeURIComponent(value.scanId)}/protocol-map?node=${encodeURIComponent(node.id)}`}>Show on Protocol Map</Link>{node.kind === "function" && node.contractId && <> · <Link href={`/hunts/${encodeURIComponent(value.scanId)}/contracts/${encodeURIComponent(node.contractId)}/functions/${encodeURIComponent(node.id)}`}>Open Function Explorer</Link></>}{["contract", "interface", "library"].includes(node.kind) && <> · <Link href={`/hunts/${encodeURIComponent(value.scanId)}/contracts/${encodeURIComponent(node.id)}`}>Open Contract Explorer</Link></>}</li>)}</ul></section> : null}
    <section className="card"><h2>Provenance</h2><div className="af-table-wrap"><table><thead><tr><th>Input artifact</th><th>Derived / linked artifact</th></tr></thead><tbody>
      {value.provenance.map((edge) => <tr key={`${edge.from}:${edge.to}`}><td className="mono">{edge.from}</td><td className="mono">{edge.to}</td></tr>)}
    </tbody></table></div></section>
    <section className="card"><h2>Assumptions and limitations</h2><h3>Assumptions</h3><ul>{value.assumptions.map((item) => <li key={item}>{item}</li>)}</ul>
      <h3>Limitations</h3><ul>{value.limitations.map((item) => <li key={item}>{item}</li>)}</ul></section>
    <section className="card"><h2>Evidence warnings</h2>{value.warnings.length ? <ul>{value.warnings.map((item) =>
      <li key={`${item.artifactId}:${item.message}`}>{item.message}{mode === "researcher" && <span className="mono"> · {item.artifactId}</span>}</li>)}</ul> : <p>No additional evidence warnings.</p>}</section>
  </div>;
}
