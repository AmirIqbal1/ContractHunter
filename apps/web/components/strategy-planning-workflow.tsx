"use client";

import { useState } from "react";
import type { VerificationStrategy } from "@contracthunter/core";
import type { HypothesisStatus } from "@contracthunter/core";
import type { PublicVerificationOption } from "@/lib/verification/public-verification-options";
import type { PublicVerificationPlanAttempt } from "@/lib/verification/public-strategy-planning";
import { planningFailureMessage, strategyNames } from "@/lib/verification/public-strategy-planning";
import type { PublicHypothesisVerificationRun } from "@/lib/verification/public-verification";
import type { PublicInvariantProposal, PublicInvariantReplayArtifact, PublicInvariantReplayRun, PublicInvariantReview, PublicInvariantRun } from "@/lib/verification/public-invariants";
import { requestSelectedStrategy } from "@/lib/verification/client-strategy-generation";
import { VerificationOptions } from "./verification-options";
import { LocalVerification } from "./local-verification";
import { LocalInvariantTesting } from "./local-invariant-testing";

type Props = { hypothesisId: string; hypothesisStatus: HypothesisStatus; options: PublicVerificationOption[]; initialAttempts: PublicVerificationPlanAttempt[]; initialVerificationRuns: PublicHypothesisVerificationRun[]; initialProposals: PublicInvariantProposal[]; initialInvariantRuns: PublicInvariantRun[]; initialReplays: PublicInvariantReplayArtifact[]; initialReplayRuns: PublicInvariantReplayRun[]; initialReviews: PublicInvariantReview[] };

export function StrategyPlanningWorkflow(props: Props) {
  const [generating, setGenerating] = useState<VerificationStrategy | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [options, setOptions] = useState(props.options);
  const [attempts, setAttempts] = useState(props.initialAttempts);
  const [selectedAttemptId, setSelectedAttemptId] = useState<string | null>(null);
  const [newProposal, setNewProposal] = useState<PublicInvariantProposal | null>(null);
  async function generate(strategy: VerificationStrategy) {
    if (generating) return;
    setGenerating(strategy); setFailure(null);
    try {
      const { ok, body } = await requestSelectedStrategy(props.hypothesisId, strategy);
      if (!ok) {
        setFailure(planningFailureMessage(body.code));
        if (body.code === "strategy_not_compatible" || body.code === "strategy_compatibility_unknown") {
          const refreshed = await fetch(`/api/hypotheses/${props.hypothesisId}/verification-options`, { cache: "no-store" }).catch(() => null);
          if (refreshed?.ok) {
            const current = await refreshed.json() as { options?: PublicVerificationOption[] };
            if (current.options) setOptions(current.options);
          }
        }
        return;
      }
      if (strategy === "structured-verification" && body.attempt?.selectedStrategy === strategy) {
        setAttempts((current) => [body.attempt!, ...current.filter((item) => item.id !== body.attempt!.id)]);
        setSelectedAttemptId(body.attempt.id);
        if (body.attempt.status === "failed") setFailure(planningFailureMessage(body.attempt.failureCode));
      } else if (body.proposal?.selectedStrategy === strategy) {
        setNewProposal(body.proposal);
        if (body.proposal.status === "failed") setFailure(planningFailureMessage(body.proposal.failureCode));
      } else setFailure("Strategy planning returned an invalid response.");
    } catch { setFailure("Strategy planning could not be reached."); }
    finally { setGenerating(null); }
  }
  return <>
    <VerificationOptions options={options} generating={generating} onGenerate={generate} />
    {failure && <p className="error" role="alert">{failure}</p>}
    {generating && <p className="verification-message" role="status">Generating {strategyNames[generating]} plan. No verification is running.</p>}
    <LocalVerification hypothesisId={props.hypothesisId} hypothesisStatus={props.hypothesisStatus} initialRuns={props.initialVerificationRuns} initialAttempts={attempts} selectedAttemptId={selectedAttemptId} />
    <LocalInvariantTesting hypothesisId={props.hypothesisId} hypothesisStatus={props.hypothesisStatus} initialProposals={props.initialProposals} incomingProposal={newProposal} initialRuns={props.initialInvariantRuns} initialReplays={props.initialReplays} initialReplayRuns={props.initialReplayRuns} initialReviews={props.initialReviews} />
  </>;
}
