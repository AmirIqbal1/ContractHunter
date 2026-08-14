"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import type { HypothesisStatus } from "@contracthunter/core";
const options: HypothesisStatus[] = ["candidate", "investigating", "likely-valid", "rejected"];
export function HypothesisStatusControl({ id, status }: { id: string; status: HypothesisStatus }) { const router = useRouter(); const [value, setValue] = useState(status); const [saving, setSaving] = useState(false); if (status === "verified") return <span className="badge green">verified</span>; return <select aria-label="Hypothesis status" disabled={saving} value={value} onChange={async (event) => { const next = event.target.value as Exclude<HypothesisStatus, "verified">; setValue(next); setSaving(true); const response = await fetch(`/api/hypotheses/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status: next }) }).catch(() => null); if (!response?.ok) setValue(status); else router.refresh(); setSaving(false); }}>{options.map((item) => <option key={item}>{item}</option>)}</select>; }
