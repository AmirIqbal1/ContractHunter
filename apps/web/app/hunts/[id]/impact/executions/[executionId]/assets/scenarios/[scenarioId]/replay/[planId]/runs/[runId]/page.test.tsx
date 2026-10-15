import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const calls = vi.hoisted(() => ({ planView: vi.fn(), result: vi.fn() }));
vi.mock("next/navigation", () => ({ notFound: () => { throw Error("not-found"); },
  useRouter: () => ({ refresh: vi.fn() }) }));
vi.mock("@contracthunter/db", () => ({ getDatabase: () => ({}),
  readScenarioReplayRun: () => ({ id: "55555555-5555-4555-8555-555555555555", planRevisionId: "revision",
    status: "failed", stopReason: "impact_server_restart" }),
  readScenarioReplayPlan: () => ({ id: "revision", planId: "44444444-4444-4444-8444-444444444444",
    scanId: "11111111-1111-4111-8111-111111111111", executionId: "22222222-2222-4222-8222-222222222222",
    scenarioId: "33333333-3333-4333-8333-333333333333", scenarioRevisionId: "source-revision",
    sessionId: "session", mode: "independent-replay", iterationCount: 2, sourceSha256: "sha256:source",
    chainId: 1, forkBlock: 1, forkBlockHash: "0xblock", forgeVersion: "forge", forgeSha256: "hash",
    assetFlowContentSha256: "e1", scenarioContentSha256: "f1", contentSha256: "plan" }),
  readImpactScenarioRevision: () => ({ subject: { type: "finding", id: "33333333-3333-4333-8333-333333333333" } }),
  readImpactForkSession: () => ({ status: "failed" }), readImpactPoCExecution: () => null }));
vi.mock("@/lib/impact-scenario-replay", () => ({ replayPlanView: calls.planView,
  readReplayResult: calls.result }));
vi.mock("@/lib/asset-flow-server", () => ({ loadAssetFlow: () => null }));
import ReplayRunPage from "./page";

const ids = { id: "11111111-1111-4111-8111-111111111111",
  executionId: "22222222-2222-4222-8222-222222222222",
  scenarioId: "33333333-3333-4333-8333-333333333333",
  planId: "44444444-4444-4444-8444-444444444444",
  runId: "55555555-5555-4555-8555-555555555555" };
describe("exact bounded replay run route", () => {
  beforeEach(() => { calls.planView.mockReset(); calls.result.mockReset(); });
  it("rejects another hunt before reading a replay result", async () => {
    calls.planView.mockImplementation(() => { throw Error("replay_plan_not_found"); });
    await expect(ReplayRunPage({ params: Promise.resolve({ ...ids,
      id: "66666666-6666-4666-8666-666666666666" }) })).rejects.toThrow("not-found");
    expect(calls.result).not.toHaveBeenCalled();
  });
  it("keeps a historical incompatible run readable as unavailable without leaking an internal failure", async () => {
    calls.planView.mockReturnValue({});
    calls.result.mockImplementation(() => { throw Error("/private/worker/socket"); });
    const html = renderToStaticMarkup(await ReplayRunPage({ params: Promise.resolve(ids) }));
    expect(html).toContain("Replay accounting unavailable");
    expect(html).toContain("IMPACT SERVER RESTART");
    expect(html).not.toContain("/private/worker/socket");
  });
});
