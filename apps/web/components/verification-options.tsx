"use client";

import { useState } from "react";
import type { VerificationStrategy } from "@contracthunter/core";
import type { PublicVerificationOption } from "@/lib/verification/public-verification-options";

type Props = { options: PublicVerificationOption[] };
const statusLabel = { compatible: "Compatible", incompatible: "Not compatible", unknown: "Unknown" } as const;
const statusTone = { compatible: "green", incompatible: "red", unknown: "amber" } as const;

export function VerificationOptions({ options }: Props) {
  const [selected, setSelected] = useState<VerificationStrategy | null>(null);
  return <section className="article-section verification-section" aria-labelledby="verification-options-heading">
    <h2 id="verification-options-heading">Verification options</h2>
    <p className="muted">This advisory check uses correlated scanner evidence and current plan capabilities. Compatible means a strategy may be expressible; a concrete plan still needs validation. The order is for display, not a recommendation.</p>
    <div className="verification-option-list">
      {options.map((option) => <div className="plan-proposal" key={option.strategy}>
        <div className="verification-option-head"><h3>{option.label}</h3><span className={`badge ${statusTone[option.compatibility]}`}>{statusLabel[option.compatibility]}</span></div>
        <p className="muted">Engine: {option.engine ?? "—"} · Plan mode: {option.planMode ?? "—"}</p>
        {option.compatibility === "compatible" && <p>Known structured requirements fit this strategy&apos;s current capability profile.</p>}
        {option.compatibility === "unknown" && <p>Compatibility could not be determined from the available structured evidence.</p>}
        {option.reasons.length > 0 && <ul className="reason-list">{option.reasons.map((reason) => <li key={`${reason.code}:${reason.requirement ?? ""}`}>{reason.message}</li>)}</ul>}
        {option.selectionAvailable && <button className="button secondary-button" type="button" aria-pressed={selected === option.strategy} onClick={() => setSelected(option.strategy)}>Select for planning</button>}
      </div>)}
    </div>
    {selected && <p className="verification-message" role="status">{options.find((option) => option.strategy === selected)?.label} selected for this page. Strategy-aware plan generation is planned for Part 2B; no plan or run was created. Existing manual workflows remain available below.</p>}
  </section>;
}
