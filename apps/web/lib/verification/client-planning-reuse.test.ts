import { afterEach, describe, expect, it, vi } from "vitest";
import type { PublicInvariantProposal } from "./public-invariants";
import type { PublicVerificationPlanAttempt } from "./public-strategy-planning";
import { performPlanningReuse, planningReuseFailureMessage, requestPlanningReuse } from "./client-planning-reuse";
import type { PlanningCandidate, PublicVerificationTargetSummary } from "./verification-target-discovery";

const requested = "11111111-1111-4111-8111-111111111111", sourceHypothesis = "22222222-2222-4222-8222-222222222222";
const sourceArtifact = "33333333-3333-4333-8333-333333333333", freshArtifact = "44444444-4444-4444-8444-444444444444";
const candidate = (strategy: PlanningCandidate["strategy"], hypothesisId = sourceHypothesis): PlanningCandidate => ({
  artifactId: sourceArtifact, artifactType: strategy === "structured-verification" ? "structured-plan" : "invariant-proposal", hypothesisId,
  strategy, propertyTargetIds: [], eligibility: "eligible", reasons: ["matching-persisted-validation"], validationState: "validated-at-execution",
  executionHistoryExists: true, createdAt: "2026-10-08T00:00:00.000Z", sourceClosureFingerprintRecorded: true,
});
const target = { candidates: [], candidateCount: 0 } as unknown as PublicVerificationTargetSummary;
const artifact = (item: PlanningCandidate) => item.artifactType === "structured-plan"
  ? { attempt: { id: freshArtifact, origin: "reused", selectedStrategy: "structured-verification", reuseSourceArtifactId: sourceArtifact } as PublicVerificationPlanAttempt }
  : { proposal: { id: freshArtifact, origin: "reused", selectedStrategy: item.strategy, reuseSourceArtifactId: sourceArtifact } as PublicInvariantProposal };
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
afterEach(() => vi.restoreAllMocks());

describe("bodyless explicit planning reuse client", () => {
  it.each(["structured-verification", "foundry-fuzz-property", "foundry-stateful-invariant", "echidna-stateful-invariant"] as const)("loads a new %s artifact through one reuse POST and one candidate refresh", async (strategy) => {
    const item = candidate(strategy);
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => String(url).includes("/reuse/") ? response(artifact(item), 201) : response({ target }));
    const started: string[] = [], success: string[] = [], failed: string[] = [], refreshed: Array<PublicVerificationTargetSummary | null> = [];
    const pending = { current: null as string | null };
    await performPlanningReuse(requested, item, pending, {
      onStart: (id) => started.push(id), onSuccess: (result, id) => success.push(`${id}:${result.artifact.id}:${result.type}`),
      onFailure: (message) => failed.push(message), onRefresh: (value) => refreshed.push(value), onFinish: () => started.push("finished"),
    });
    expect(started).toEqual([sourceArtifact, "finished"]);
    expect(success).toEqual([`${sourceArtifact}:${freshArtifact}:${item.artifactType}`]);
    expect(failed).toEqual([]); expect(refreshed).toEqual([target]); expect(pending.current).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0]).toEqual([`/api/hypotheses/${requested}/verification-target/reuse/${item.artifactType === "structured-plan" ? "structured" : "invariant"}/${sourceArtifact}`, { method: "POST" }]);
    expect(fetcher.mock.calls[1]).toEqual([`/api/hypotheses/${requested}/verification-target`, { cache: "no-store" }]);
    expect(fetcher.mock.calls.every(([url]) => !/verification-options|verification-plan$|invariant-proposals$|\/verify$|\/run\//.test(String(url)))).toBe(true);
  });
  it("prevents a second click while one request is in flight, then permits another deliberate reuse", async () => {
    const item = candidate("structured-verification", requested);
    let release: ((value: Response) => void) | undefined;
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation((url) => String(url).includes("/reuse/") ? new Promise<Response>((resolve) => { release = resolve; }) : Promise.resolve(response({ target })));
    const pending = { current: null as string | null }, successes: string[] = [];
    const handlers = { onStart: vi.fn(), onSuccess: (result: { artifact: { id: string } }) => successes.push(result.artifact.id), onFailure: vi.fn(), onRefresh: vi.fn(), onFinish: vi.fn() };
    const first = performPlanningReuse(requested, item, pending, handlers);
    await performPlanningReuse(requested, item, pending, handlers);
    expect(fetcher).toHaveBeenCalledTimes(1); expect(pending.current).toBe(sourceArtifact);
    release!(response(artifact(item), 201)); await first;
    expect(successes).toEqual([freshArtifact]); expect(pending.current).toBeNull();
    const second = performPlanningReuse(requested, item, pending, handlers);
    release!(response(artifact(item), 201)); await second;
    expect(successes).toEqual([freshArtifact, freshArtifact]);
    expect(fetcher).toHaveBeenCalledTimes(4);
  });
  it.each(["reuse_source_changed", "reuse_compiler_mismatch", "reuse_target_changed", "reuse_strategy_mismatch", "reuse_property_target_mismatch", "reuse_alignment_unavailable", "reuse_authoritative_profile_unsupported", "reuse_concrete_strategy_incompatible", "reuse_candidate_not_eligible"])("shows bounded %s failure and refreshes without a generation fallback", async (code) => {
    const item = candidate("echidna-stateful-invariant");
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => String(url).includes("/reuse/") ? response({ code }, 409) : response({ target }));
    const failures: string[] = [], refreshed: boolean[] = [];
    await performPlanningReuse(requested, item, { current: null }, { onStart: vi.fn(), onSuccess: vi.fn(), onFailure: (message) => failures.push(message), onRefresh: (value, failed) => { expect(value).toEqual(target); refreshed.push(failed); }, onFinish: vi.fn() });
    expect(failures).toEqual([planningReuseFailureMessage(code)]); expect(refreshed).toEqual([true]);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.every(([url]) => !/verification-options|verification-plan$|invariant-proposals$|\/run\//.test(String(url)))).toBe(true);
  });
  it("refuses an ineligible browser candidate and treats hostile or malformed responses as bounded failures", async () => {
    const item = { ...candidate("structured-verification"), eligibility: "incompatible" as const };
    const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(response({ code: "reuse_source_changed" }, 409));
    await performPlanningReuse(requested, item, { current: null }, { onStart: vi.fn(), onSuccess: vi.fn(), onFailure: vi.fn(), onRefresh: vi.fn(), onFinish: vi.fn() });
    expect(fetcher).not.toHaveBeenCalled();
    expect(planningReuseFailureMessage("/private/path\nstack trace")).toBe("Planning reuse failed safely.");
    fetcher.mockResolvedValue(response({ code: "/private/path", attempt: { id: freshArtifact } }, 201));
    expect(await requestPlanningReuse(requested, candidate("structured-verification"))).toEqual({ ok: false, message: "Planning reuse returned an invalid response." });
  });
});
