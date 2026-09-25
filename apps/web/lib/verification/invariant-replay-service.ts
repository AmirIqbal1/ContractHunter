import { randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { counterexampleHash, executableInvariantEvidenceSchema, executableInvariantPlanSchema, invariantReplayManifestFingerprint, invariantReplayPlanHash, invariantReplayPlanSchema, loadConfig, stableCompilerVersionSchema, type InvariantReplayPlan } from "@contracthunter/core";
import { createInvariantReplayArtifact, createInvariantReplayRun, finishInvariantReplayRun, getExecutableInvariantProposal, getExecutableInvariantRun, getInvariantReplayArtifact, getScan, getVulnerabilityHypothesis, listInvariantReplayArtifacts, markInvariantReplayRunRunning, reviewReproducedInvariantEvidence, type DatabaseClient, type InvariantEvidenceReviewRow, type InvariantReplayArtifactRow, type InvariantReplayRunRow, getDatabase } from "@contracthunter/db";
import { InvariantReplayWorkerClient, VerificationWorkspaceBuilder, validateInvariantReplayWorkspaceIntegrity, type InvariantReplayWorkerResult } from "@contracthunter/scanners";

export class InvariantReplayRequestError extends Error { constructor(readonly code: "unknown_run" | "unknown_replay" | "invalid_state" | "replay_unavailable", message: string) { super(message); this.name = "InvariantReplayRequestError"; } }
type BuiltReplay = Awaited<ReturnType<VerificationWorkspaceBuilder["buildInvariantReplay"]>>;
export type InvariantReplayServiceOptions = { database: DatabaseClient; repositoryRoot: string; verificationRoot: string; workspaceBuilder: (compilers: string[]) => { buildInvariantReplay(input: { workspaceId: string; repositoryPath: string; replayPlan: InvariantReplayPlan; invariantPlan: ReturnType<typeof executableInvariantPlanSchema.parse> }): Promise<BuiltReplay> }; runner: { run(input: Parameters<InvariantReplayWorkerClient["run"]>[0]): Promise<InvariantReplayWorkerResult> }; validateIntegrity?: typeof validateInvariantReplayWorkspaceIntegrity };
const parse = (value: string | null): unknown => { try { return JSON.parse(value ?? "null") as unknown; } catch { return null; } };

export class InvariantReplayService {
  constructor(private readonly options: InvariantReplayServiceOptions) {}
  private async repository(hypothesisId: string, proposalId: string, runId: string) {
    const hypothesis = getVulnerabilityHypothesis(this.options.database, hypothesisId), proposal = getExecutableInvariantProposal(this.options.database, proposalId), run = getExecutableInvariantRun(this.options.database, runId);
    if (!hypothesis || !proposal || !run || proposal.hypothesisId !== hypothesisId || run.hypothesisId !== hypothesisId || proposal.scanId !== hypothesis.scanId || run.scanId !== hypothesis.scanId) throw new InvariantReplayRequestError("unknown_run", "Invariant run was not found for this proposal.");
    if (hypothesis.status === "rejected" || proposal.status !== "generated" || proposal.hypothesisExpectation !== "hypothesis-predicts-property-violation" || !proposal.plan || !proposal.planHash || run.status !== "completed" || run.outcome !== "counterexample-found" || run.planHash !== proposal.planHash) throw new InvariantReplayRequestError("invalid_state", "This invariant result is not replayable.");
    const invariant = executableInvariantPlanSchema.safeParse(parse(run.plan)), evidence = executableInvariantEvidenceSchema.array().safeParse(parse(run.dynamicEvidence));
    if (!invariant.success || !evidence.success) throw new InvariantReplayRequestError("invalid_state", "Persisted invariant evidence is invalid.");
    const failing = evidence.data.filter((item) => item.propertyOutcome === "counterexample-found" && item.hypothesisRelation === "unreviewed" && item.counterexample);
    if (failing.length !== 1) throw new InvariantReplayRequestError("replay_unavailable", "Replay requires exactly one bounded counterexample.");
    const scan = getScan(this.options.database, hypothesis.scanId), compilers = stableCompilerVersionSchema.array().safeParse(parse(scan?.compilerVersions ?? null));
    if (!scan || scan.resolvedCommit !== invariant.data.resolvedCommit || !compilers.success || !compilers.data.includes(invariant.data.compilerVersion)) throw new InvariantReplayRequestError("invalid_state", "Trusted scan identity changed.");
    const root = await realpath(this.options.repositoryRoot).catch(() => { throw new InvariantReplayRequestError("invalid_state", "Repository root is unavailable."); }), expected = path.join(root, scan.id), info = await lstat(expected).catch(() => { throw new InvariantReplayRequestError("invalid_state", "Prepared repository is unavailable."); });
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(expected) !== expected) throw new InvariantReplayRequestError("invalid_state", "Prepared repository is unsafe.");
    return { hypothesis, proposal, run, invariant: invariant.data, evidence: failing[0], compilers: compilers.data, repositoryPath: expected };
  }
  async generate(hypothesisId: string, proposalId: string, runId: string): Promise<InvariantReplayArtifactRow> {
    const existing = listInvariantReplayArtifacts(this.options.database, runId).find((item) => item.proposalId === proposalId); if (existing) return existing;
    const bound = await this.repository(hypothesisId, proposalId, runId), artifactId = randomUUID(), counterexample = bound.evidence.counterexample!;
    const replayPlan = invariantReplayPlanSchema.parse({ schemaVersion: "contracthunter-invariant-replay-v1", hypothesisId, scanId: bound.invariant.scanId, resolvedCommit: bound.invariant.resolvedCommit, compilerVersion: bound.invariant.compilerVersion, proposalId, invariantRunId: runId, invariantPlanHash: bound.proposal.planHash, propertyName: bound.evidence.propertyName, hypothesisExpectation: bound.proposal.hypothesisExpectation, counterexample, counterexampleHash: counterexampleHash(counterexample) });
    const built = await this.options.workspaceBuilder(bound.compilers).buildInvariantReplay({ workspaceId: artifactId, repositoryPath: bound.repositoryPath, replayPlan, invariantPlan: bound.invariant });
    const validated = await (this.options.validateIntegrity ?? validateInvariantReplayWorkspaceIntegrity)(built.workspacePath);
    if (JSON.stringify(validated) !== JSON.stringify(built.manifest) || built.manifest.replayPlanHash !== invariantReplayPlanHash(replayPlan)) throw new InvariantReplayRequestError("invalid_state", "Generated replay workspace failed validation.");
    return createInvariantReplayArtifact(this.options.database, { id: artifactId, proposalId, invariantRunId: runId, replayPlan, harnessHash: built.manifest.generatedHarnessSha256, contentFingerprint: built.manifest.contentFingerprint });
  }
  async execute(hypothesisId: string, replayArtifactId: string): Promise<InvariantReplayRunRow> {
    const artifact = getInvariantReplayArtifact(this.options.database, replayArtifactId); if (!artifact || artifact.hypothesisId !== hypothesisId) throw new InvariantReplayRequestError("unknown_replay", "Replay artifact not found.");
    const bound = await this.repository(hypothesisId, artifact.proposalId, artifact.invariantRunId), replayPlan = invariantReplayPlanSchema.safeParse(parse(artifact.replayPlan));
    if (!replayPlan.success || invariantReplayPlanHash(replayPlan.data) !== artifact.replayPlanHash || counterexampleHash(replayPlan.data.counterexample) !== artifact.counterexampleHash) throw new InvariantReplayRequestError("invalid_state", "Replay artifact identity is invalid.");
    const run = createInvariantReplayRun(this.options.database, artifact.id); markInvariantReplayRunRunning(this.options.database, run.id); let result: InvariantReplayWorkerResult | undefined; const started = Date.now();
    try {
      const built = await this.options.workspaceBuilder(bound.compilers).buildInvariantReplay({ workspaceId: run.id, repositoryPath: bound.repositoryPath, replayPlan: replayPlan.data, invariantPlan: bound.invariant });
      const manifest = await (this.options.validateIntegrity ?? validateInvariantReplayWorkspaceIntegrity)(built.workspacePath);
      const { contentFingerprint: _freshFingerprint, ...freshBase } = manifest;
      void _freshFingerprint;
      const artifactFingerprint = invariantReplayManifestFingerprint({ ...freshBase, workspaceId: artifact.id });
      if (JSON.stringify(manifest) !== JSON.stringify(built.manifest) || artifactFingerprint !== artifact.contentFingerprint || manifest.generatedHarnessSha256 !== artifact.harnessHash || manifest.replayPlanHash !== artifact.replayPlanHash || manifest.replayPlan.counterexampleHash !== artifact.counterexampleHash) throw new Error("replay_manifest_mismatch");
      result = await this.options.runner.run({ replayRunId: run.id, workspacePath: built.workspacePath, scanId: replayPlan.data.scanId, hypothesisId, resolvedCommit: replayPlan.data.resolvedCommit, compilerVersion: replayPlan.data.compilerVersion, invariantPlanHash: replayPlan.data.invariantPlanHash, replayPlanHash: artifact.replayPlanHash, counterexampleHash: artifact.counterexampleHash });
      const trusted = result.status === "completed" && !!result.isolation && !result.timedOut && !result.outputTruncated && !result.errorCode && result.outcome !== null;
      return finishInvariantReplayRun(this.options.database, run.id, { outcome: trusted ? result.outcome! : result.status === "refused" ? "refused" : "failed", exitCode: result.exitCode, timedOut: result.timedOut, errorCode: trusted ? null : result.errorCode ?? "replay_result_unparseable", isolationMetadata: result.isolation ? JSON.stringify(result.isolation).slice(0, 4096) : null, durationMs: result.durationMs });
    } catch (error) { const code = error instanceof Error && /^[a-z_]{1,80}$/.test(error.message) ? error.message : "replay_workspace_invalid"; return finishInvariantReplayRun(this.options.database, run.id, { outcome: "failed", exitCode: result?.exitCode ?? null, timedOut: result?.timedOut ?? false, errorCode: result?.errorCode ?? code, isolationMetadata: result?.isolation ? JSON.stringify(result.isolation).slice(0, 4096) : null, durationMs: result?.durationMs ?? Date.now() - started }); }
  }
  review(hypothesisId: string, proposalId: string, runId: string, replayRunId: string): InvariantEvidenceReviewRow { return reviewReproducedInvariantEvidence(this.options.database, { hypothesisId, proposalId, invariantRunId: runId, replayRunId }); }
}
export function createInvariantReplayService(database: DatabaseClient = getDatabase()): InvariantReplayService { const config = loadConfig(), verificationRoot = process.env.VERIFICATION_ROOT ?? path.join(config.DATA_DIR, "verifications"); return new InvariantReplayService({ database, repositoryRoot: config.REPOSITORY_DIR, verificationRoot, runner: new InvariantReplayWorkerClient(verificationRoot), workspaceBuilder: (compilers) => new VerificationWorkspaceBuilder({ verificationRoot, repositoryRoot: config.REPOSITORY_DIR, acceptedCompilerVersions: compilers, approvedSourceRoots: ["src", "contracts", "lib", "node_modules"], generatorVersion: "0.2.0" }) }); }
