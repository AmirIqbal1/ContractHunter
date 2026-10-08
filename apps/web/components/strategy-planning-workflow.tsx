"use client";

import { useRef, useState } from "react";
import type { VerificationStrategy } from "@contracthunter/core";
import type { HypothesisStatus } from "@contracthunter/core";
import type { PublicVerificationOption } from "@/lib/verification/public-verification-options";
import type { PublicVerificationPlanAttempt } from "@/lib/verification/public-strategy-planning";
import { planningFailureMessage, strategyNames } from "@/lib/verification/public-strategy-planning";
import type { PublicHypothesisVerificationRun } from "@/lib/verification/public-verification";
import type { PublicInvariantProposal, PublicInvariantReplayArtifact, PublicInvariantReplayRun, PublicInvariantReview, PublicInvariantRun } from "@/lib/verification/public-invariants";
import { requestSelectedStrategy } from "@/lib/verification/client-strategy-generation";
import { performPlanningReuse } from "@/lib/verification/client-planning-reuse";
import type { PlanningCandidate, PublicVerificationTargetSummary } from "@/lib/verification/verification-target-discovery";
import { VerificationOptions } from "./verification-options";
import { VerificationTargetSection } from "./verification-target-section";
import { LocalVerification } from "./local-verification";
import { LocalInvariantTesting } from "./local-invariant-testing";

type Props = { hypothesisId: string; hypothesisStatus: HypothesisStatus; target: PublicVerificationTargetSummary | null; options: PublicVerificationOption[]; initialAttempts: PublicVerificationPlanAttempt[]; initialVerificationRuns: PublicHypothesisVerificationRun[]; initialProposals: PublicInvariantProposal[]; initialInvariantRuns: PublicInvariantRun[]; initialReplays: PublicInvariantReplayArtifact[]; initialReplayRuns: PublicInvariantReplayRun[]; initialReviews: PublicInvariantReview[] };

export function StrategyPlanningWorkflow(props: Props) {
  const [generating, setGenerating] = useState<VerificationStrategy | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [options, setOptions] = useState(props.options);
  const [attempts, setAttempts] = useState(props.initialAttempts);
  const [selectedAttemptId, setSelectedAttemptId] = useState<string | null>(null);
  const [createdProposals, setCreatedProposals] = useState<PublicInvariantProposal[]>([]);
  const [selectedProposalId, setSelectedProposalId] = useState<string | null>(null);
  const [target, setTarget] = useState(props.target);
  const [reusingId, setReusingId] = useState<string | null>(null);
  const pendingReuse = useRef<string | null>(null);
  const [reuseFeedback, setReuseFeedback] = useState<{ artifactId: string; message: string; failed: boolean } | null>(null);
  async function reuse(candidate: PlanningCandidate) {
    if (props.hypothesisStatus === "rejected") return;
    await performPlanningReuse(props.hypothesisId, candidate, pendingReuse, {
      onStart: (id) => { setReusingId(id); setReuseFeedback(null); },
      onSuccess: (result, sourceId) => {
        if (result.type === "structured-plan" && "result" in result.artifact) {
          const attempt = result.artifact;
          setAttempts((current) => [attempt, ...current.filter((item) => item.id !== attempt.id)]);
          setSelectedAttemptId(attempt.id);
          setReuseFeedback({ artifactId: sourceId, message: `New structured planning artifact ${attempt.id.slice(0, 8)} is ready for review and explicit validation.`, failed: false });
        } else if (result.type === "invariant-proposal" && "planHash" in result.artifact) {
          const proposal = result.artifact;
          setCreatedProposals((current) => [proposal, ...current.filter((item) => item.id !== proposal.id)]);
          setSelectedProposalId(proposal.id);
          setReuseFeedback({ artifactId: sourceId, message: `New invariant proposal ${proposal.id.slice(0, 8)} is ready for review and explicit validation.`, failed: false });
        }
      },
      onFailure: (message, sourceId) => setReuseFeedback({ artifactId: sourceId, message, failed: true }),
      onRefresh: (refreshed, failed) => {
        if (refreshed) setTarget(refreshed);
        else if (failed) setTarget((current) => current ? { ...current, candidates: [], candidateCount: 0 } : null);
      },
      onFinish: () => setReusingId(null),
    });
  }
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
        setCreatedProposals((current) => [body.proposal!, ...current.filter((item) => item.id !== body.proposal!.id)]);
        setSelectedProposalId(body.proposal.id);
        if (body.proposal.status === "failed") setFailure(planningFailureMessage(body.proposal.failureCode));
      } else setFailure("Strategy planning returned an invalid response.");
    } catch { setFailure("Strategy planning could not be reached."); }
    finally { setGenerating(null); }
  }
  return <>
    {target && <VerificationTargetSection target={target} requestedHypothesisId={props.hypothesisId} onReuse={props.hypothesisStatus === "rejected" ? undefined : reuse} reusingId={reusingId} reuseFeedback={reuseFeedback} />}
    <VerificationOptions options={options} generating={generating} onGenerate={generate} />
    {failure && <p className="error" role="alert">{failure}</p>}
    {generating && <p className="verification-message" role="status">Generating {strategyNames[generating]} plan. No verification is running.</p>}
    <LocalVerification hypothesisId={props.hypothesisId} hypothesisStatus={props.hypothesisStatus} initialRuns={props.initialVerificationRuns} initialAttempts={attempts} selectedAttemptId={selectedAttemptId} />
    <LocalInvariantTesting hypothesisId={props.hypothesisId} hypothesisStatus={props.hypothesisStatus} initialProposals={props.initialProposals} incomingProposal={createdProposals[0] ?? null} additionalProposals={createdProposals.slice(1)} selectedProposalId={selectedProposalId} initialRuns={props.initialInvariantRuns} initialReplays={props.initialReplays} initialReplayRuns={props.initialReplayRuns} initialReviews={props.initialReviews} />
  </>;
}
