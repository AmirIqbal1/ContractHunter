import { describe, expect, it } from "vitest";
import { buildEvidencePackage, evidenceArtifact, type EvidenceArtifact, type EvidencePackage } from "./evidence-package";
import { buildBountyReport, defaultBountyReportFields, renderBountyReportMarkdown,
  verifyBountyReportIntegrity, type BountyReport } from "./bounty-report";

const scanId = "11111111-1111-4111-8111-111111111111";
const subjectId = "22222222-2222-4222-8222-222222222222";
const packageId = "33333333-3333-4333-8333-333333333333";
const executionId = "44444444-4444-4444-8444-444444444444";
const scenarioId = "55555555-5555-4555-8555-555555555555";
const replayId = "66666666-6666-4666-8666-666666666666";
function art(type: string, id: string, data: unknown, provenance: string[] = [subjectId],
  status: EvidenceArtifact["status"] = "available") {
  return evidenceArtifact({ type, id, schemaVersion: `${type}-v1`, status, sourceContentHash: null,
    provenance, recordCount: 1, data });
}
function pkg(options: { dynamic?: boolean; scenario?: boolean; replay?: "independent-replay" | "cumulative-replay";
  stopped?: boolean; partial?: boolean; sensitive?: boolean; jsonSecret?: boolean; longTrace?: boolean } = {}): EvidencePackage {
  const artifacts: EvidenceArtifact[] = [art("static-context", subjectId, { findings: [{ id: subjectId,
    contract: "Vault", functionName: "withdraw", sourceUnit: "src/Vault.sol", startLine: 10, endLine: 12,
    scanner: "slither", detectorId: "detector", status: "candidate", existingSeverity: "medium" }],
    ...(options.jsonSecret ? { apiKey: "fixture-secret" } : {}) }, []),
  art("source", "source", { sourceUnit: "src/Vault.sol", rawSha256: "snapshot-hash", startLine: 9,
    endLine: 12, excerpt: options.sensitive ? "// /home/user/.secret" : "// α\r\ncontract Vault {}" }),
  art("investigation-path", "path", { paths: [{ kind: "caller-chain", completeness: "complete-within-bounds",
    steps: [{ label: "Router.deposit()" }, { label: "Vault.withdraw()" }] }] })];
  if (options.dynamic) {
    artifacts.push(art("reviewed-poc", "poc", { id: "poc", sourceSha256: "source-hash",
      source: "contract PoC {\n```\n}", entryContract: "PoC", forgeVersion: "1.7.1", forgeSha256: "forge-hash" }));
    artifacts.push(art("fork-identity", "fork", { chainId: 1, forkBlock: 123, forkBlockHash: "0xblock",
      targetCodeHashes: { "0x1111111111111111111111111111111111111111": "code-hash" } }, ["poc"]));
    artifacts.push(art("execution", executionId, { id: executionId, status: "completed", executed: true,
      transactionHashes: ["0xtx"], traceCaptureStatus: options.partial ? "failed" : "finalized",
      finalReset: "unavailable" }, ["poc", "fork"]));
    artifacts.push(art("trace", "trace", { traces: options.partial ? [] : [{ id: "trace-id", transactionHash: "0xtx",
      transactionOrdinal: 0, receipt: { status: 1, blockNumber: 124, blockHash: "0xlocal", gasUsed: "900719925474099312345" },
      nodes: [{ ordinal: 0, depth: 0, callType: "CALL", from: "0xaaa", to: "0xbbb",
        selector: "0x12345678", inputByteLength: 4, inputSha256: "sha256:input", outcome: "success", valueWei: "0" },
      { ordinal: 1, depth: 1, callType: "STATICCALL", from: "0xbbb", to: "0xccc",
        selector: "0x87654321", inputByteLength: 4, inputSha256: "sha256:oracle", outcome: "reverted", valueWei: "0" },
      ...(options.longTrace ? Array.from({ length: 126 }, (_, i) => ({ ordinal: i + 2, depth: 1,
        callType: "CALL", from: "0xbbb", to: "0xddd", selector: "0x12345678",
        inputByteLength: 4, inputSha256: "sha256:input", outcome: "success", valueWei: "0" })) : [])] }] },
    [executionId], options.partial ? "partial" : "available"));
    artifacts.push(art("impact-overlay", "overlay", { transactions: [{ ordinal: 0, transactionHash: "0xtx",
      sender: "0xaaa", to: "0xbbb", valueWei: "0", status: "success", localBlockNumber: 124,
      localBlockHash: "0xlocal", gasUsed: "900719925474099312345" }],
      calls: [{ relationshipStatus: "runtime-only-observed" }, { relationshipStatus: "unmapped-runtime-call" }],
      pathComparisons: [{ pathId: "path", edges: [{ edgeId: "edge", status: "not-observed-in-this-execution" }] }],
      coverage: { unmappedCallCount: 1 } }, [executionId]));
    artifacts.push(art("state", "state", { diff: options.partial ? null : { changes: [{ id: "native:0xaaa",
      kind: "native", before: "900719925474099312345", after: "900719925474099312344", delta: "-1",
      beforeStatus: "available", afterStatus: "available" }] } }, [executionId], options.partial ? "partial" : "available"));
    const assets = ["ETH", "TOKEN_A", "TOKEN_B", "NFT"];
    artifacts.push(art("asset-flow", "flow", { status: options.partial ? "partial" : "complete-within-evidence",
      participants: [{ address: "0xaaa", label: "Mapped protocol contract" },
        { address: "0xbbb", label: "Unmapped address" },
        { address: "0xccc", label: "Unmapped address" }],
      ledgerEntries: assets.map((assetId, i) => ({ id: `entry-${i}`, transactionOrdinal: 0, assetId,
        from: "0xaaa", to: "0xbbb", amount: assetId === "NFT" ? "1" : `${i + 1}000`,
        movementKind: "observed-transfer", evidenceId: `evidence-${i}` })),
      netPositions: assets.map((assetId, i) => ({ participant: "0xbbb", assetId,
        incoming: assetId === "NFT" ? "1" : `${i + 1}000`, outgoing: "0",
        netObservedMovement: assetId === "NFT" ? "1" : `${i + 1}000` })),
      reconciliation: [{ observationId: "native:0xaaa", status: "partial", before: "1000", after: "999",
        ledgerNet: "-1", difference: "0" }] }, [executionId], options.partial ? "partial" : "available"));
  }
  if (options.scenario || options.replay) {
    artifacts.push(art("reviewed-scenario", scenarioId, { id: scenarioId, scenarioId, revision: 1,
      status: "reviewed" }, ["flow"]));
    artifacts.push(art("scenario-accounting", "accounting", { roles: [{ role: "scenario-subject", address: "0xbbb" },
      { role: "protocol", address: "0xaaa" }], rolePositions: [{ transactionOrdinal: null, assetId: "TOKEN_A",
      role: "scenario-subject", incoming: "2000", outgoing: "0", netObservedMovement: "2000" }],
      directRoleTransfers: [{ transactionOrdinal: null, assetId: "TOKEN_A", direction: "protocol-to-subject",
        amount: "2000", ledgerEntryIds: ["entry-1"] }] }, [scenarioId]));
  }
  if (options.replay) {
    const stopped = !!options.stopped;
    artifacts.push(art("replay", replayId, { plan: { id: "plan", mode: options.replay, iterationCount: stopped ? 5 : 3 },
      run: { id: replayId, status: stopped ? "failed" : "completed", finalReset: "successful",
        stopReason: stopped ? "unexpected-outcome" : null }, result: {
        mode: options.replay, requestedIterations: stopped ? 5 : 3, completedIterations: 3,
        matchingIterations: options.replay === "independent-replay" ? 3 : 0,
        repeatability: stopped ? "partial" : options.replay === "independent-replay" ? "reproduced-consistently" : "stopped-after-state-change",
        stopReason: stopped ? "unexpected-outcome" : null,
        iterations: [1, 2, 3, ...(stopped ? [4] : [])].map((index) => ({ iteration: { index,
          status: index === 4 ? "failed" : "completed", stopReason: index === 4 ? "unexpected-outcome" : null },
          matchedReference: options.replay === "independent-replay" && index < 4, variation: [] })),
        cumulativePositions: options.replay === "cumulative-replay" ? [{ assetId: "TOKEN_A", role: "protocol",
          incoming: "0", outgoing: "6000", netObservedMovement: "-6000" }] : [],
        cumulativeDirect: [] } }, [scenarioId, executionId], stopped ? "partial" : "available"));
  }
  return buildEvidencePackage({ packageId, huntId: scanId, scanId,
    subject: { type: "finding", id: subjectId, title: "Unicode α finding", status: "candidate",
      existingSeverity: "medium", existingConfidence: 80 },
    selection: { executionId: options.dynamic ? executionId : null,
      scenarioRevisionId: options.scenario || options.replay ? scenarioId : null,
      replayRunId: options.replay ? replayId : null }, status: "finalized", artifacts, warnings: [],
    createdAt: 1, finalizedAt: 2 });
}
function make(packageValue: EvidencePackage): BountyReport {
  return buildBountyReport(packageValue, { ...defaultBountyReportFields(packageValue), summary: "Researcher α note" },
    { reportId: "77777777-7777-4777-8777-777777777777", revisionOf: null,
      status: "finalized", createdAt: 3, finalizedAt: 4 });
}
describe("G2 report coverage", () => {
  it("keeps a static-only report free of PoC and impact claims", () => {
    const report = make(pkg()), markdown = renderBountyReportMarkdown(report);
    expect(report.packageCompleteness).toBe("static-only");
    expect(report.sections.map((s) => s.id)).not.toContain("reproduction");
    expect(report.sections.map((s) => s.id)).not.toContain("asset-movement");
    expect(markdown).toContain("Router.deposit\\(\\) → Vault.withdraw\\(\\)");
    expect(markdown).toContain("src/Vault.sol");
    expect(markdown).toContain("Researcher α note");
  });
  it("includes one reviewed execution with exact receipt, trace, state and local-fork facts", () => {
    const markdown = renderBountyReportMarkdown(make(pkg({ dynamic: true })));
    expect(markdown).toContain("No transaction was sent to the upstream/live network.");
    expect(markdown).toContain("0xlocal");
    expect(markdown).toContain("900719925474099312345");
    expect(markdown).toContain("STATICCALL");
    expect(markdown).toContain("native:0xaaa");
    expect(markdown).toContain("Automated reproduction command reconstruction is unavailable");
    expect(markdown).not.toContain("/home/");
  });
  it("separates independent 3/3 repeatability from four asset movements", () => {
    const report = make(pkg({ dynamic: true, scenario: true, replay: "independent-replay" }));
    const markdown = renderBountyReportMarkdown(report);
    expect(markdown).toContain("3 of 3 bounded independent repetitions");
    expect(markdown).toContain("Their movements are not summed as cumulative impact.");
    for (const asset of ["ETH", "TOKEN\\_A", "TOKEN\\_B", "NFT"]) expect(markdown).toContain(asset);
    expect(markdown).not.toContain("Completed-iteration direct amount");
    expect(report.sections.map((s) => s.id)).toContain("scenario-analysis");
    expect(report.sections.map((s) => s.id)).toContain("static-vs-observed");
    expect(markdown).toContain("0xccc | unassigned");
    expect(markdown).toContain("runtime-only-observed");
    expect(markdown).toContain("unmapped-runtime-call");
    expect(markdown).toContain("not-observed-in-this-execution");
  });
  it("reports only completed cumulative movement and a factual early stop", () => {
    const markdown = renderBountyReportMarkdown(make(pkg({ dynamic: true, scenario: true,
      replay: "cumulative-replay", stopped: true })));
    expect(markdown).toContain("| Requested iterations | 5 |");
    expect(markdown).toContain("| Completed iterations | 3 |");
    expect(markdown).toContain("| TOKEN\\_A | protocol | 0 | 6000 | -6000 |");
    expect(markdown).toContain("unexpected-outcome");
    expect(markdown).not.toContain("maximum is 3");
    expect(markdown).not.toContain("18,000");
  });
  it("renders partial evidence as partial and bounds long traces", () => {
    const report = make(pkg({ dynamic: true, partial: true }));
    expect(report.packageCompleteness).toBe("dynamic-partial");
    const markdown = renderBountyReportMarkdown(report);
    expect(markdown).toContain("State diff unavailable or partial");
    expect(markdown).toContain("Asset accounting is partial");
  });
  it("bounds long normalized trace presentation while keeping its G1 evidence reference", () => {
    const report = make(pkg({ dynamic: true, longTrace: true }));
    const trace = report.sections.find((item) => item.id === "trace");
    const callTable = trace?.blocks.find((block) => block.kind === "table" && block.columns.includes("Call ID"));
    expect(callTable?.kind === "table" && callTable.rows.length).toBeLessThanOrEqual(24);
    expect(renderBountyReportMarkdown(report)).toContain("omitted. Full normalized trace remains in the G1 package.");
  });
  it("rejects secret and host-path fields and packages", () => {
    const safe = pkg();
    expect(() => buildBountyReport(safe, { ...defaultBountyReportFields(safe), summary: "rpc_url=https://private.invalid" },
      { reportId: "x", revisionOf: null, status: "draft", createdAt: 3, finalizedAt: null }))
      .toThrow("bounty_report_sensitive_content_detected");
    expect(() => make(pkg({ sensitive: true }))).toThrow("bounty_report_sensitive_content_detected");
    expect(() => make(pkg({ jsonSecret: true }))).toThrow("bounty_report_sensitive_content_detected");
  });
  it("verifies report/package hashes and deterministic UTF-8 LF Markdown", () => {
    const originalPackage = pkg(), report = make(originalPackage);
    expect(verifyBountyReportIntegrity(report, originalPackage)).toEqual({ status: "valid", reasons: [] });
    expect(verifyBountyReportIntegrity(report, null).status).toBe("unavailable");
    expect(verifyBountyReportIntegrity({ ...report, contentHash: "sha256:bad" }, originalPackage).status).toBe("invalid");
    expect(verifyBountyReportIntegrity(report, { ...originalPackage, contentHash: "sha256:bad" }).status).toBe("invalid");
    const first = renderBountyReportMarkdown(report), second = renderBountyReportMarkdown(report);
    expect(Buffer.from(first).equals(Buffer.from(second))).toBe(true);
    expect(first).toContain("Unicode α finding");
    expect(first).not.toContain("\r");
  });
});
