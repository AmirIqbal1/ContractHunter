import type { VerificationStrategy } from "@contracthunter/core";
import type { PublicInvariantProposal } from "./public-invariants";
import type { PublicVerificationPlanAttempt } from "./public-strategy-planning";

type GenerationResponse = { code?: string; attempt?: PublicVerificationPlanAttempt; proposal?: PublicInvariantProposal };
/** Browser submits only the closed route identity. All planning inputs are reloaded by the server. */
export async function requestSelectedStrategy(hypothesisId: string, strategy: VerificationStrategy, send: typeof fetch = fetch): Promise<{ ok: boolean; body: GenerationResponse }> {
  const response = await send(`/api/hypotheses/${hypothesisId}/verification-options/${strategy}/generate`, { method: "POST" });
  const body = await response.json() as GenerationResponse;
  return { ok: response.ok, body };
}
