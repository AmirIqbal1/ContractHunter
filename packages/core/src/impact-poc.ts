import { createHash } from "node:crypto";
import { z } from "zod";
import { impactObservationPlanInputSchema } from "./impact-state";
import { containsCredentialOrEndpointText } from "./sensitive-export";

const id = z.string().uuid();
const source = z.string().min(1).max(16_384).superRefine((value, context) => {
  const raw = Buffer.from(value, "utf8");
  if (raw.length > 16_384 || new TextDecoder("utf-8", { fatal: true }).decode(raw) !== value ||
    /\bimport\b/.test(value) || /\u0000/.test(value) || containsCredentialOrEndpointText(value) ||
    !/pragma\s+solidity\s+0\.8\.36\s*;/.test(value))
    context.addIssue({ code: "custom", message: "impact_poc_source_invalid" });
});
export const impactPoCCreateSchema = z.object({
  findingId: id.optional(), hypothesisId: id.optional(), revisionOf: id.optional(),
  filename: z.literal("ImpactPoC.s.sol"), source,
  entryContract: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
}).strict().refine((value) => Number(Boolean(value.findingId)) + Number(Boolean(value.hypothesisId)) === 1,
  { message: "exactly one finding or hypothesis ID is required" });
export const impactPoCExecutionSchema = z.object({ pocArtifactId: id,
  observations: impactObservationPlanInputSchema.optional() }).strict();
export const impactPoCReviewSchema = z.object({ decision: z.enum(["reviewed", "rejected"]) }).strict();
export type ImpactPoCCreate = z.infer<typeof impactPoCCreateSchema>;
export type ImpactPoCReviewState = "draft" | "reviewed" | "rejected";
export type ImpactPoCExecutionStatus = "created" | "queued" | "running" | "completed" | "failed" | "cancelled";
export function impactPoCSourceHash(value: string): string { return `sha256:${createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex")}`; }
