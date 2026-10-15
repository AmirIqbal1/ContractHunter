import { createHash } from "node:crypto";

export const EVIDENCE_PACKAGE_SCHEMA = "contracthunter-evidence-package-v1" as const;
export const EVIDENCE_PACKAGE_RULESET = "contracthunter-evidence-package-ruleset-v1" as const;
export const EVIDENCE_PACKAGE_LIMITS = { artifacts: 32, artifactBytes: 2_500_000,
  packageBytes: 15_000_000, warnings: 128, excerptLines: 31, excerptBytes: 8_192 } as const;
export type EvidenceSubject = { type: "finding" | "investigation" | "hypothesis"; id: string;
  title: string; status: string; existingSeverity: string | null; existingConfidence: number | null };
export type EvidenceArtifact = { type: string; id: string; schemaVersion: string; status: "available" | "partial" | "unavailable";
  sourceContentHash: string | null; contentHash: string; provenance: string[]; recordCount: number | null;
  data: unknown };
export type EvidenceManifestEntry = Omit<EvidenceArtifact, "data">;
export type EvidencePackage = { schema: typeof EVIDENCE_PACKAGE_SCHEMA; rulesetVersion: typeof EVIDENCE_PACKAGE_RULESET;
  packageId: string; huntId: string; scanId: string; subject: EvidenceSubject;
  selection: { executionId: string | null; scenarioRevisionId: string | null; replayRunId: string | null };
  status: "draft" | "finalized"; completeness: "static-only" | "dynamic-partial" | "dynamic-complete-within-evidence";
  capabilities: Record<string, "available" | "partial" | "unavailable">;
  executionEnvironment: "isolated-local-fork" | null; localExecutionStatement: string | null;
  artifacts: EvidenceArtifact[]; manifest: EvidenceManifestEntry[]; manifestHash: string;
  provenance: Array<{ from: string; to: string }>; assumptions: string[]; limitations: string[];
  warnings: Array<{ artifactId: string; message: string }>;
  createdAt: number; finalizedAt: number | null; contentHash: string };

/** Canonical JSON accepts exact integer strings, never unsafe JSON numbers or executable values. */
export function canonicalEvidenceJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw Error("evidence_unsafe_number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalEvidenceJson).join(",")}]`;
  if (typeof value === "object" && value && Object.getPrototypeOf(value) === Object.prototype) {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => {
      if (object[key] === undefined) throw Error("evidence_undefined_value");
      return `${JSON.stringify(key)}:${canonicalEvidenceJson(object[key])}`;
    }).join(",")}}`;
  }
  throw Error("evidence_non_json_value");
}
export function evidenceHash(domain: string, value: unknown): string {
  return `sha256:${createHash("sha256").update(domain).update("\0").update(canonicalEvidenceJson(value)).digest("hex")}`;
}
export function evidenceArtifact(input: Omit<EvidenceArtifact, "contentHash">): EvidenceArtifact {
  const serialized = canonicalEvidenceJson(input.data);
  if (Buffer.byteLength(serialized) > EVIDENCE_PACKAGE_LIMITS.artifactBytes)
    throw Error("evidence_artifact_size_limit");
  return { ...input, data: JSON.parse(serialized) as unknown,
    provenance: [...new Set(input.provenance)].sort(),
    contentHash: evidenceHash(`${EVIDENCE_PACKAGE_SCHEMA}:artifact:${input.type}`, input.data) };
}
export function buildEvidencePackage(input: Omit<EvidencePackage, "schema" | "rulesetVersion" | "manifest" |
  "manifestHash" | "contentHash" | "provenance" | "completeness" | "capabilities" | "executionEnvironment" |
  "localExecutionStatement" | "assumptions" | "limitations">): EvidencePackage {
  if (input.artifacts.length > EVIDENCE_PACKAGE_LIMITS.artifacts || input.warnings.length > EVIDENCE_PACKAGE_LIMITS.warnings)
    throw Error("evidence_package_size_limit");
  const artifacts = input.artifacts.map((item) => {
    const normalized = evidenceArtifact({ type: item.type, id: item.id,
      schemaVersion: item.schemaVersion, status: item.status, sourceContentHash: item.sourceContentHash,
      provenance: item.provenance, recordCount: item.recordCount, data: item.data });
    if (normalized.contentHash !== item.contentHash) throw Error("evidence_artifact_hash_invalid");
    return normalized;
  }).sort((a, b) => `${a.type}:${a.id}`.localeCompare(`${b.type}:${b.id}`));
  if (new Set(artifacts.map((item) => `${item.type}:${item.id}`)).size !== artifacts.length)
    throw Error("evidence_duplicate_artifact");
  const warnings = [...input.warnings].sort((a, b) => `${a.artifactId}:${a.message}`.localeCompare(`${b.artifactId}:${b.message}`));
  const manifest = artifacts.map((item) => ({ type: item.type, id: item.id,
    schemaVersion: item.schemaVersion, status: item.status, sourceContentHash: item.sourceContentHash,
    contentHash: item.contentHash, provenance: item.provenance, recordCount: item.recordCount }));
  const ids = new Set(artifacts.map((item) => item.id));
  const provenance = artifacts.flatMap((item) => item.provenance.map((from) => ({ from, to: item.id })))
    .sort((a, b) => `${a.to}:${a.from}`.localeCompare(`${b.to}:${b.from}`));
  if (provenance.some((edge) => !ids.has(edge.from) && edge.from !== input.subject.id))
    throw Error("evidence_dangling_provenance");
  const dynamic = input.selection.executionId !== null;
  const byType = new Map(artifacts.map((item) => [item.type, item.status]));
  const capabilities = Object.fromEntries(["static-context", "source", "investigation-path", "reviewed-poc",
    "fork-identity", "execution", "trace", "state", "impact-overlay", "asset-flow", "reviewed-scenario",
    "scenario-accounting", "replay"].map((type) => [type, byType.get(type) ?? "unavailable"])) as Record<string, EvidenceArtifact["status"]>;
  const required = ["reviewed-poc", "fork-identity", "execution", "trace", "state", "asset-flow"];
  const completeness: EvidencePackage["completeness"] = !dynamic ? "static-only" : required.every((type) => capabilities[type] === "available") &&
    artifacts.every((item) => !["scenario-accounting", "replay", "replay-iteration"].includes(item.type) || item.status === "available") ?
      "dynamic-complete-within-evidence" : "dynamic-partial";
  const assumptions = ["Source context uses immutable scan-time snapshots where available.",
    "Asset amounts are exact raw units; no price conversion is applied.",
    ...(dynamic ? ["Dynamic execution used the exact reviewed PoC on an isolated local fork."] : []),
    ...(input.selection.replayRunId ? ["Replay used only the requested bounded iterations."] : [])];
  const limitations = ["Static investigation paths are research context, not exploit proof.",
    "State capture observes a bounded set of accounts and storage; unavailable is not zero.",
    "State changes alone do not prove causality to a trace call.",
    "No fiat valuation, severity inference, or maximum-drain analysis is included.",
    ...(dynamic ? ["Local-fork evidence is not a live-chain transaction."] : []),
    ...(input.selection.scenarioRevisionId ? ["Scenario roles are reviewed researcher annotations, not protocol identity facts."] : []),
    ...(input.selection.replayRunId ? ["Bounded replay does not establish unlimited repeatability, maximum protocol impact, or real-chain exploitability."] : [])];
  const manifestHash = evidenceHash(`${EVIDENCE_PACKAGE_SCHEMA}:manifest`, manifest);
  const semantic = { rulesetVersion: EVIDENCE_PACKAGE_RULESET, huntId: input.huntId, scanId: input.scanId,
    subject: input.subject, selection: input.selection, completeness, capabilities, artifacts,
    manifestHash, provenance, assumptions, limitations, warnings };
  const contentHash = evidenceHash(EVIDENCE_PACKAGE_SCHEMA, semantic);
  const result: EvidencePackage = { schema: EVIDENCE_PACKAGE_SCHEMA, ...semantic, packageId: input.packageId,
    status: input.status, manifest, executionEnvironment: dynamic ? "isolated-local-fork" : null,
    localExecutionStatement: dynamic ? "Dynamic evidence was produced against ContractHunter's isolated local fork. No transaction was sent to the upstream/live network." : null,
    createdAt: input.createdAt, finalizedAt: input.finalizedAt, contentHash };
  if (Buffer.byteLength(canonicalEvidenceJson(result)) > EVIDENCE_PACKAGE_LIMITS.packageBytes)
    throw Error("evidence_package_size_limit");
  return result;
}
export function verifyEvidencePackageIntegrity(value: EvidencePackage): { status: "valid" | "invalid" | "unavailable"; reasons: string[] } {
  try {
    if (!value?.artifacts || !value.manifest) return { status: "unavailable", reasons: ["package_artifacts_unavailable"] };
    for (const artifact of value.artifacts) {
      if (evidenceArtifact({ type: artifact.type, id: artifact.id, schemaVersion: artifact.schemaVersion,
        status: artifact.status, sourceContentHash: artifact.sourceContentHash,
        provenance: artifact.provenance, recordCount: artifact.recordCount,
        data: artifact.data }).contentHash !== artifact.contentHash)
      return { status: "invalid", reasons: [`artifact_hash_invalid:${artifact.type}`] };
    }
    const rebuilt = buildEvidencePackage({ packageId: value.packageId, huntId: value.huntId, scanId: value.scanId,
      subject: value.subject, selection: value.selection, status: value.status, artifacts: value.artifacts,
      warnings: value.warnings, createdAt: value.createdAt, finalizedAt: value.finalizedAt });
    if (canonicalEvidenceJson(rebuilt.manifest) !== canonicalEvidenceJson(value.manifest))
      return { status: "invalid", reasons: ["manifest_entries_invalid"] };
    if (rebuilt.manifestHash !== value.manifestHash) return { status: "invalid", reasons: ["manifest_hash_invalid"] };
    if (rebuilt.contentHash !== value.contentHash) return { status: "invalid", reasons: ["package_hash_invalid"] };
    if (canonicalEvidenceJson(rebuilt) !== canonicalEvidenceJson(value))
      return { status: "invalid", reasons: ["package_fields_invalid"] };
    return { status: "valid", reasons: [] };
  } catch { return { status: "invalid", reasons: ["package_integrity_invalid"] }; }
}
