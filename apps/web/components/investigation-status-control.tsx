"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { InvestigationStatus } from "@contracthunter/core";

const investigationStatuses: InvestigationStatus[] = ["candidate", "investigating", "verified", "rejected"];

export function InvestigationStatusControl({ id, status }: { id: string; status: InvestigationStatus }) {
  const router = useRouter();
  const [value, setValue] = useState(status);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  async function update(next: InvestigationStatus) {
    setValue(next); setSaving(true); setError("");
    const response = await fetch(`/api/investigations/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status: next }) }).catch(() => null);
    if (!response?.ok) { setValue(status); setError("Status update failed."); }
    else router.refresh();
    setSaving(false);
  }
  return <div><select aria-label="Investigation status" value={value} disabled={saving} onChange={(event) => void update(event.target.value as InvestigationStatus)}>{investigationStatuses.map((item) => <option key={item}>{item}</option>)}</select>{error && <div className="error" style={{ marginTop: 8, marginBottom: 0 }}>{error}</div>}</div>;
}
