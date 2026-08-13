"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import type { InvariantStatus } from "@contracthunter/core";
const options: InvariantStatus[] = ["proposed", "accepted", "rejected"];
export function InvariantStatusControl({ id, status }: { id: string; status: InvariantStatus }) {
  const router = useRouter(); const [value, setValue] = useState(status); const [saving, setSaving] = useState(false);
  if (!options.includes(status)) return <span className="badge gray">{status}</span>;
  return <select aria-label="Invariant status" disabled={saving} value={value} onChange={async (event) => { const next = event.target.value as InvariantStatus; setValue(next); setSaving(true); const response = await fetch(`/api/invariants/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status: next }) }).catch(() => null); if (!response?.ok) setValue(status); else router.refresh(); setSaving(false); }}>{options.map((item) => <option key={item}>{item}</option>)}</select>;
}
