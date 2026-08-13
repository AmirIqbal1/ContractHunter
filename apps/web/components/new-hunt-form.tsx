"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

export function NewHuntForm() {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setSubmitting(true); setError(undefined);
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ repositoryUrl: form.get("repositoryUrl"), requestedRef: form.get("requestedRef"), depth: form.get("depth") }) });
      const body = await response.json() as { scan?: { id: string }; error?: string };
      if (!response.ok || !body.scan) throw new Error(body.error ?? "Unable to start hunt.");
      router.push(`/hunts/${body.scan.id}`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to start hunt."); setSubmitting(false); }
  }

  return <form className="card form-card" onSubmit={submit}>
    <div className="mock-note">ContractHunter detects and prepares trusted Solidity compilers automatically. Project dependencies must already exist in the repository.</div>
    {error && <div className="error">{error}</div>}
    <div className="field"><label htmlFor="repositoryUrl">GitHub repository URL</label><input required id="repositoryUrl" name="repositoryUrl" type="url" placeholder="https://github.com/owner/repository" autoComplete="off" /><span className="hint">Only GitHub HTTPS repository URLs are accepted.</span></div>
    <div className="field"><label htmlFor="requestedRef">Branch, tag, or commit <span className="muted">(optional)</span></label><input id="requestedRef" name="requestedRef" placeholder="main" autoComplete="off" /><span className="hint">Leave blank to scan the repository&apos;s default branch.</span></div>
    <div className="field"><label htmlFor="depth">Scan depth</label><select id="depth" name="depth" defaultValue="quick"><option value="quick">Quick</option><option value="deep">Deep</option><option value="maximum">Maximum</option></select><span className="hint">Depth is recorded in V0.1.6; all options currently run the same static analysis.</span></div>
    <button className="button" disabled={submitting}>{submitting ? "QUEUING…" : "START HUNT"}</button>
  </form>;
}
