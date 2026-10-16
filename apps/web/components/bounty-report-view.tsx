"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import type { BountyReport, BountyReportFields } from "@contracthunter/core";
import { BountyReportPaper } from "./bounty-report-paper";
import { copyBountyReportMarkdown } from "@/lib/bounty-report-copy";

export function BountyReportView({ value, scanId, fieldLimits, revision }: { value: BountyReport; scanId: string;
  fieldLimits: Record<keyof BountyReportFields, number>; revision: number }) {
  const router = useRouter();
  const [fields, setFields] = useState<BountyReportFields>(value.fields);
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const [mode, setMode] = useState<"beginner" | "researcher">("beginner");
  const dirty = JSON.stringify(fields) !== JSON.stringify(value.fields);
  const base = `/api/scans/${encodeURIComponent(scanId)}/impact/evidence-packages/${encodeURIComponent(value.evidencePackageId)}/reports`;
  const here = `/hunts/${encodeURIComponent(scanId)}/evidence-packages/${encodeURIComponent(value.evidencePackageId)}/reports/${encodeURIComponent(value.reportId)}`;
  async function action(kind: "save" | "finalize" | "revise") {
    setBusy(true); setError("");
    try {
      const url = kind === "revise" ? base : kind === "finalize" ? `${base}/${value.reportId}/finalize` : `${base}/${value.reportId}`;
      const response = await fetch(url, { method: kind === "save" ? "PATCH" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(kind === "save" ? fields : kind === "revise" ? { revisionOf: value.reportId } : {}) });
      if (!response.ok) throw Error("Report action failed. Check field bounds and package integrity.");
      const result = await response.json() as { reportId: string };
      if (kind === "revise") router.push(`${here.slice(0, here.lastIndexOf("/"))}/${result.reportId}`);
      router.refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Report action failed."); }
    finally { setBusy(false); }
  }
  async function copyMarkdown() {
    setError(""); setNotice("");
    try {
      await copyBountyReportMarkdown(`${base}/${value.reportId}/download`, fetch,
        (markdown) => navigator.clipboard.writeText(markdown));
      setNotice("Markdown copied exactly from the finalized download.");
    } catch { setError("Markdown could not be copied. Use Download Markdown instead."); }
  }
  const edit = value.status === "draft";
  const fieldLabels: Array<[keyof BountyReportFields, string]> = [["title", "Report title"], ["summary", "Short summary"],
    ["impactStatement", "Impact statement"], ["reproductionNote", "Reproduction note"], ["additionalContext", "Additional context"]];
  return <div className="af-view bounty-report"><header className="page-head"><div>
    <div className="eyebrow">{edit ? "DRAFT BUG-BOUNTY REPORT" : "FINALIZED BUG-BOUNTY REPORT"}</div>
    <h1>{value.fields.title}</h1><p className="subhead">Bound to finalized Evidence Package {value.evidencePackageId}.</p>
  </div></header>
    <nav className="ip-actions bounty-controls"><Link href={`/hunts/${encodeURIComponent(scanId)}/evidence-packages/${encodeURIComponent(value.evidencePackageId)}`}>View Evidence Package</Link>
      {value.status === "finalized" && <><a href={`${base}/${value.reportId}/download`}>Download Markdown</a>
        <button type="button" onClick={copyMarkdown}>Copy Markdown</button>
        <Link href={`${here}/print`}>Print view</Link>
        <button type="button" disabled={busy} onClick={() => action("revise")}>Edit Report (new draft revision)</button></>}</nav>
    {error && <p role="alert" className="af-warning">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    <div className="af-mode bounty-controls" role="group" aria-label="Report presentation mode">
      {(["beginner", "researcher"] as const).map((item) => <button key={item} type="button" aria-pressed={mode === item}
        onClick={() => setMode(item)}>{item === "beginner" ? "Beginner" : "Researcher"}</button>)}
    </div>
    {mode === "beginner" && <section className="card bounty-controls"><h2>About this report</h2>
      <p>Report: A human-readable write-up built from the frozen Evidence Package.</p>
      <p>Evidence Package: The underlying machine-readable evidence.</p>
      <p>Report Hash: A fingerprint of the finalized report content.</p></section>}
    <div className="bounty-banners" aria-label="Evidence boundaries">
      {value.packageCompleteness === "static-only" && <strong>STATIC ONLY</strong>}
      {value.packageCompleteness === "dynamic-partial" && <strong>PARTIAL EVIDENCE</strong>}
      {value.capabilities.execution !== "unavailable" && <strong>LOCAL FORK</strong>}
      {value.capabilities.replay !== "unavailable" && <strong>BOUNDED REPLAY</strong>}
      {value.capabilities["reviewed-scenario"] !== "unavailable" && <strong>MANUAL SCENARIO ROLES</strong>}
    </div>
    {edit && <section className="card bounty-editor"><h2>Researcher-authored fields</h2>
      <p>These fields are narrative annotations. The evidence sections below are read only.</p>
      {fieldLabels.map(([key, label]) => <label key={key} className="bounty-field"><span>{label} · {fieldLimits[key]} UTF-8 bytes max</span>
        {key === "title" ? <input value={fields[key]} maxLength={fieldLimits[key]}
          onChange={(event) => setFields({ ...fields, [key]: event.target.value })} /> :
          <textarea value={fields[key]} rows={key === "summary" ? 4 : 6} maxLength={fieldLimits[key]}
            onChange={(event) => setFields({ ...fields, [key]: event.target.value })} />}</label>)}
      <div className="ip-actions"><button type="button" disabled={busy || !dirty} onClick={() => action("save")}>Save draft</button>
        <button type="button" disabled={busy || dirty} onClick={() => action("finalize")}>Finalize report</button></div>
      {dirty && <p>Save draft to refresh the preview before finalizing.</p>}</section>}
    <section className="card bounty-controls"><h2>Report status and integrity</h2><dl className="io-grid">
      <div><dt>Report ID</dt><dd className="mono">{value.reportId}</dd></div>
      <div><dt>Revision</dt><dd>{revision}</dd></div>
      <div><dt>Status</dt><dd>{value.status}</dd></div>
      <div><dt>Evidence capability</dt><dd>{value.packageCompleteness}</dd></div>
      <div><dt>Created</dt><dd>{new Date(value.createdAt).toISOString()}</dd></div>
      <div><dt>Finalized</dt><dd>{value.finalizedAt === null ? "Unavailable" : new Date(value.finalizedAt).toISOString()}</dd></div>
      <div><dt>Package ID</dt><dd className="mono">{value.evidencePackageId}</dd></div>
      <div><dt>Report content hash</dt><dd className="mono">{value.contentHash}</dd></div>
      <div><dt>Package content hash</dt><dd className="mono">{value.evidencePackageContentHash}</dd></div>
      <div><dt>Manifest hash</dt><dd className="mono">{value.evidenceManifestHash}</dd></div>
      {mode === "researcher" && <><div><dt>Report schema / ruleset</dt><dd className="mono">{value.schema} · {value.rulesetVersion}</dd></div>
        <div><dt>Integrity</dt><dd>Valid (verified against finalized G1 package)</dd></div>
        <div><dt>Export filename</dt><dd className="mono">contracthunter-report-{value.reportId}.md</dd></div></>}
    </dl></section>
    <BountyReportPaper value={value} />
  </div>;
}
