"use client";

import type { VerificationStrategy } from "@contracthunter/core";
import type { PublicVerificationOption } from "@/lib/verification/public-verification-options";

type Props = { options: PublicVerificationOption[]; generating?: VerificationStrategy | null; onGenerate?: (strategy: VerificationStrategy) => void };
const statusLabel = { compatible: "Compatible", incompatible: "Not compatible", unknown: "Unknown" } as const;
const statusTone = { compatible: "green", incompatible: "red", unknown: "amber" } as const;

export function VerificationOptions({ options, generating = null, onGenerate }: Props) {
  return <section className="article-section verification-section" aria-labelledby="verification-options-heading">
    <h2 id="verification-options-heading">Verification options</h2>
    <p className="muted">This advisory check uses correlated scanner evidence and current plan capabilities. Compatible means its abstract capabilities appear sufficient. A generated plan still needs concrete validation. Display order carries no ranking.</p>
    <div className="verification-option-list">
      {options.map((option) => <div className="plan-proposal" key={option.strategy}>
        <div className="verification-option-head"><h3>{option.label}</h3><span className={`badge ${statusTone[option.compatibility]}`}>{statusLabel[option.compatibility]}</span></div>
        <p className="muted">Engine: {option.engine ?? "—"} · Plan mode: {option.planMode ?? "—"}</p>
        {option.compatibility === "compatible" && <p>Known structured requirements fit this strategy&apos;s current capability profile.</p>}
        {option.compatibility === "unknown" && <p>Compatibility could not be determined from the available structured evidence.</p>}
        {option.reasons.length > 0 && <ul className="reason-list">{option.reasons.map((reason) => <li key={`${reason.code}:${reason.requirement ?? ""}`}>{reason.message}</li>)}</ul>}
        {option.selectionAvailable && <button className="button secondary-button" type="button" disabled={!!generating || !onGenerate} onClick={() => onGenerate?.(option.strategy)}>{generating === option.strategy ? "Generating…" : "Generate plan"}</button>}
      </div>)}
    </div>
  </section>;
}
