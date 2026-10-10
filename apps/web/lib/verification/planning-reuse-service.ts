import { buildInvariantPropertyTargets, executableInvariantPlanSchema, fingerprintAuthoritativeSourceClosure, invariantPlanHash,
  stableCompilerVersionSchema, verificationHarnessPlanSchema, type ExecutableInvariantPlan, type VerificationHarnessPlan,
  type VerificationStrategy } from "@contracthunter/core";
import { ExecutableInvariantGenerator, validateEchidnaPlanCompatibility } from "@contracthunter/scanners";
import { assessPersistedHypothesisVerificationStrategies, createReusedInvariantProposal, createReusedVerificationPlanAttempt,
  getExecutableInvariantProposal, getScan, getScanCompilation, getVerificationPlanAttempt, getVulnerabilityHypothesis,
  listExecutableInvariantProposals, listExecutableInvariantRuns, listHypothesisVerificationRuns,
  listPersistedInvariantPropertyTargets, listPersistedVerificationTargetGroups, type DatabaseClient } from "@contracthunter/db";
import { AuthoritativeSourceError, requireAuthoritativeSourceClosureForHypothesis, textSources } from "./authoritative-source-authority";
import { validateAuthoritativeStaticPlan } from "./verification-plan-generation-service";

export const planningReuseFailureCodes = [
  "reuse_artifact_not_found", "reuse_candidate_not_eligible", "reuse_source_identity_unprovable", "reuse_source_changed",
  "reuse_scan_mismatch", "reuse_commit_mismatch", "reuse_compiler_mismatch", "reuse_target_changed",
  "reuse_strategy_mismatch", "reuse_mode_mismatch", "reuse_property_target_mismatch", "reuse_alignment_unavailable",
  "reuse_concrete_strategy_incompatible", "reuse_authoritative_profile_unsupported", "reuse_plan_invalid",
] as const;
export type PlanningReuseFailureCode = typeof planningReuseFailureCodes[number];
export class PlanningReuseError extends Error {
  constructor(readonly code: PlanningReuseFailureCode) { super(code); this.name = "PlanningReuseError"; }
}
function fail(code: PlanningReuseFailureCode): never { throw new PlanningReuseError(code); }
const parse = (value: string | null): unknown => { try { return JSON.parse(value ?? "null") as unknown; } catch { return null; } };

function propertyIds(plan: ExecutableInvariantPlan): string[] {
  return buildInvariantPropertyTargets([{ proposalId: "source", plan }]).map((item) => item.id).sort();
}
function modeFor(strategy: Exclude<VerificationStrategy, "structured-verification">) {
  return strategy === "foundry-fuzz-property" ? "fuzz-property" : "stateful-invariant";
}
function engineFor(strategy: Exclude<VerificationStrategy, "structured-verification">) {
  return strategy === "echidna-stateful-invariant" ? "echidna" : "foundry";
}

export class PlanningReuseService {
  constructor(private readonly database: DatabaseClient) {}

  private current(requestedHypothesisId: string, sourceHypothesisId: string, sourcePlan: VerificationHarnessPlan | ExecutableInvariantPlan,
    fingerprintFields: { schema: string | null; sha256: string | null; fileCount: number | null; totalBytes: number | null },
    strategy: VerificationStrategy, sourceCompilerArtifactSha256: string | null) {
    const requested = getVulnerabilityHypothesis(this.database, requestedHypothesisId);
    const original = getVulnerabilityHypothesis(this.database, sourceHypothesisId);
    if (!requested || !original || requested.status === "rejected" || original.status === "rejected") fail("reuse_candidate_not_eligible");
    const scan = getScan(this.database, requested.scanId);
    if (!scan || scan.status !== "completed") fail("reuse_candidate_not_eligible");
    if (requested.scanId !== original.scanId || sourcePlan.scanId !== requested.scanId) fail("reuse_scan_mismatch");
    if (!scan.resolvedCommit || sourcePlan.resolvedCommit !== scan.resolvedCommit) fail("reuse_commit_mismatch");
    if (!["ready", "cached"].includes(scan.compilerStatus)) fail("reuse_compiler_mismatch");
    const trusted = stableCompilerVersionSchema.array().min(1).max(32).safeParse(parse(scan.compilerVersions));
    if (!trusted.success || !trusted.data.includes(sourcePlan.compilerVersion)) fail("reuse_compiler_mismatch");
    const groups = listPersistedVerificationTargetGroups(this.database, scan.id);
    const target = groups.find((item) => item.members.includes(requested.id));
    if (!target || !target.members.includes(original.id) || target.groupingConfidence === "insufficient-to-group" ||
        !target.contractIdentity || !target.functionName || target.contractIdentity.contract !== sourcePlan.primaryContract ||
        target.contractIdentity.sourcePath !== sourcePlan.primarySourcePath) fail("reuse_target_changed");
    const sourceAssessment = assessPersistedHypothesisVerificationStrategies(this.database, original.id);
    const requestedAssessment = assessPersistedHypothesisVerificationStrategies(this.database, requested.id);
    if (sourceAssessment?.strategies.find((item) => item.strategy === strategy)?.compatibility !== "compatible" ||
        requestedAssessment?.strategies.find((item) => item.strategy === strategy)?.compatibility !== "compatible") fail("reuse_strategy_mismatch");
    let compilation: ReturnType<typeof getScanCompilation>;
    try { compilation = getScanCompilation(this.database, scan.id); }
    catch { fail("reuse_alignment_unavailable"); }
    if (compilation.status !== "supported" || compilation.manifest.compilationProfileKind !== "plain-solidity-exact-pragma-v1" ||
        compilation.manifest.remappings.length || compilation.manifest.libraryRoots.length) fail("reuse_authoritative_profile_unsupported");
    if (!fingerprintFields.schema || !fingerprintFields.sha256 || fingerprintFields.fileCount === null || fingerprintFields.totalBytes === null)
      fail("reuse_source_identity_unprovable");
    if (compilation.manifest.compiler.version !== sourcePlan.compilerVersion) fail("reuse_compiler_mismatch");
    if (sourceCompilerArtifactSha256 && compilation.manifest.compiler.artifactSha256 !== sourceCompilerArtifactSha256)
      fail("reuse_compiler_mismatch");
    let authority: ReturnType<typeof requireAuthoritativeSourceClosureForHypothesis>;
    try {
      authority = requireAuthoritativeSourceClosureForHypothesis(this.database, requested, { sourceUnitName: sourcePlan.primarySourcePath, contract: sourcePlan.primaryContract });
      const sourceAuthority = requireAuthoritativeSourceClosureForHypothesis(this.database, original, { sourceUnitName: sourcePlan.primarySourcePath, contract: sourcePlan.primaryContract });
      if (sourceAuthority.closure.targetSourceUnit !== authority.closure.targetSourceUnit || sourceAuthority.targetContract !== authority.targetContract) fail("reuse_target_changed");
    } catch (error) {
      if (error instanceof PlanningReuseError) throw error;
      if (error instanceof AuthoritativeSourceError && ["authority_unavailable", "unsupported_profile"].includes(error.code)) fail("reuse_authoritative_profile_unsupported");
      fail("reuse_alignment_unavailable");
    }
    const fingerprint = fingerprintAuthoritativeSourceClosure(authority.closure);
    if (fingerprint.schema !== fingerprintFields.schema || fingerprint.sha256 !== fingerprintFields.sha256 ||
        fingerprint.fileCount !== fingerprintFields.fileCount || fingerprint.totalBytes !== fingerprintFields.totalBytes) fail("reuse_source_changed");
    const sources = textSources(authority.closure);
    return { requested, original, scan, target, compilation: compilation.manifest, closure: authority.closure, fingerprint, sources };
  }

  reuseStructured(requestedHypothesisId: string, sourceArtifactId: string) {
    return this.database.sqlite.transaction(() => {
      const source = getVerificationPlanAttempt(this.database, sourceArtifactId);
      if (!source || source.status !== "generated" || !source.plan) fail("reuse_artifact_not_found");
      if (source.selectedStrategy !== "structured-verification") fail("reuse_strategy_mismatch");
      const parsed = verificationHarnessPlanSchema.safeParse(parse(source.plan));
      if (!parsed.success || JSON.stringify(parsed.data) !== source.plan || parsed.data.hypothesisId !== source.hypothesisId || parsed.data.scanId !== source.scanId) fail("reuse_plan_invalid");
      const current = this.current(requestedHypothesisId, source.hypothesisId, parsed.data, {
        schema: source.sourceClosureFingerprintSchema, sha256: source.sourceClosureFingerprintSha256,
        fileCount: source.sourceClosureFingerprintFileCount, totalBytes: source.sourceClosureFingerprintTotalBytes,
      }, "structured-verification", source.reuseCompilerArtifactSha256);
      if (!parsed.data.relevantFunctions.includes(current.target.functionName!) ||
          !parsed.data.sourceFiles.every((name) => current.sources.has(name))) fail("reuse_target_changed");
      const witness = listHypothesisVerificationRuns(this.database, source.hypothesisId).some((run) =>
        run.scanId === source.scanId && run.resolvedCommit === parsed.data.resolvedCommit &&
        run.compilerVersion === parsed.data.compilerVersion && JSON.stringify(parse(run.verificationPlan)) === source.plan);
      if (!witness) fail("reuse_candidate_not_eligible");
      const rebound = verificationHarnessPlanSchema.parse({ ...parsed.data, hypothesisId: requestedHypothesisId });
      try { validateAuthoritativeStaticPlan(rebound, current.sources); }
      catch { fail("reuse_plan_invalid"); }
      return createReusedVerificationPlanAttempt(this.database, { hypothesisId: requestedHypothesisId, scanId: current.scan.id,
        sourceArtifactId: source.id, targetId: current.target.id, compilerArtifactSha256: current.compilation.compiler.artifactSha256,
        plan: rebound, sourceClosureFingerprint: current.fingerprint });
    })();
  }

  reuseInvariant(requestedHypothesisId: string, sourceArtifactId: string) {
    return this.database.sqlite.transaction(() => {
      const source = getExecutableInvariantProposal(this.database, sourceArtifactId);
      if (!source || source.status !== "generated" || !source.plan || !source.planHash) fail("reuse_artifact_not_found");
      const strategy = source.selectedStrategy;
      if (!strategy || strategy === "structured-verification") fail("reuse_strategy_mismatch");
      const parsed = executableInvariantPlanSchema.safeParse(parse(source.plan));
      if (!parsed.success || JSON.stringify(parsed.data) !== source.plan || parsed.data.hypothesisId !== source.hypothesisId ||
          parsed.data.scanId !== source.scanId || invariantPlanHash(parsed.data) !== source.planHash) fail("reuse_plan_invalid");
      if (parsed.data.mode !== modeFor(strategy)) fail("reuse_mode_mismatch");
      const current = this.current(requestedHypothesisId, source.hypothesisId, parsed.data, {
        schema: source.sourceClosureFingerprintSchema, sha256: source.sourceClosureFingerprintSha256,
        fileCount: source.sourceClosureFingerprintFileCount, totalBytes: source.sourceClosureFingerprintTotalBytes,
      }, strategy, source.reuseCompilerArtifactSha256);
      const actions = parsed.data.mode === "fuzz-property" ? [parsed.data.fuzzAction.functionName] : parsed.data.handlerActions.map((action) => action.functionName);
      if (!actions.includes(current.target.functionName!) || !parsed.data.sourceFiles.every((name) => current.sources.has(name))) fail("reuse_target_changed");
      const witness = listExecutableInvariantRuns(this.database, source.hypothesisId).some((run) =>
        run.proposalId === source.id && run.planHash === source.planHash && run.engine === engineFor(strategy) &&
        run.mode === parsed.data.mode && run.scanId === source.scanId && run.resolvedCommit === parsed.data.resolvedCommit &&
        run.compilerVersion === parsed.data.compilerVersion);
      if (!witness) fail("reuse_candidate_not_eligible");
      const rebound = executableInvariantPlanSchema.parse({ ...parsed.data, hypothesisId: requestedHypothesisId });
      const originalProperties = propertyIds(parsed.data), currentProperties = propertyIds(rebound);
      if (!originalProperties.length || JSON.stringify(originalProperties) !== JSON.stringify(currentProperties) ||
          !listPersistedInvariantPropertyTargets(this.database, [source.hypothesisId]).some((item) => originalProperties.includes(item.id) && item.members.some((member) => member.proposalId === source.id)))
        fail("reuse_property_target_mismatch");
      if (requestedHypothesisId !== source.hypothesisId) {
        const prior = listExecutableInvariantProposals(this.database, requestedHypothesisId).filter((item) => item.status === "generated" && item.selectedStrategy === strategy && item.plan);
        if (prior.length && !listPersistedInvariantPropertyTargets(this.database, [requestedHypothesisId]).some((item) => currentProperties.includes(item.id)))
          fail("reuse_property_target_mismatch");
      }
      try { new ExecutableInvariantGenerator().generate(rebound, current.sources); }
      catch { fail("reuse_plan_invalid"); }
      if (strategy === "echidna-stateful-invariant" && !validateEchidnaPlanCompatibility(rebound, current.sources).compatible)
        fail("reuse_concrete_strategy_incompatible");
      return createReusedInvariantProposal(this.database, { hypothesisId: requestedHypothesisId, scanId: current.scan.id,
        sourceArtifactId: source.id, targetId: current.target.id, compilerArtifactSha256: current.compilation.compiler.artifactSha256,
        selectedStrategy: strategy, plan: rebound, sourceClosureFingerprint: current.fingerprint,
        sourceHashes: Object.fromEntries(current.closure.files.map((file) => [file.sourceUnitName, file.rawSha256])) });
    })();
  }
}
