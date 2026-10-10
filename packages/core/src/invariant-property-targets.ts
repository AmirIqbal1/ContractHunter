import { createHash } from "node:crypto";
import { executableInvariantPlanSchema, type ExecutableInvariantPlan } from "./executable-invariant";

export type InvariantPropertyTarget = { id: string; scanId: string; primaryContract: string; primarySourcePath: string; mode: ExecutableInvariantPlan["mode"]; members: Array<{ proposalId: string; hypothesisId: string; propertyName: string }> };

/** Exact canonical semantics only. Cosmetic property/assertion labels do not create identity. */
export function buildInvariantPropertyTargets(inputs: Array<{ proposalId: string; plan: unknown }>): InvariantPropertyTarget[] {
  const groups = new Map<string, InvariantPropertyTarget>();
  for (const input of [...inputs].sort((a, b) => a.proposalId.localeCompare(b.proposalId))) {
    const parsed = executableInvariantPlanSchema.safeParse(input.plan);
    if (!parsed.success) continue;
    const plan = parsed.data;
    const properties = plan.mode === "fuzz-property" ? [plan.property] : plan.properties;
    for (const property of properties) {
      const semantics = {
        scanId: plan.scanId, primaryContract: plan.primaryContract, primarySourcePath: plan.primarySourcePath,
        mode: plan.mode, resolvedCommit: plan.resolvedCommit, compilerVersion: plan.compilerVersion, sourceFiles: [...plan.sourceFiles].sort(), setup: plan.setup,
        action: plan.mode === "fuzz-property" ? plan.fuzzAction : plan.handlerActions,
        observations: property.observations,
        assertions: property.assertions.map((assertion) => Object.fromEntries(Object.entries(assertion).filter(([key]) => key !== "id"))),
      };
      const id = createHash("sha256").update(JSON.stringify(semantics)).digest("hex");
      const group = groups.get(id) ?? { id, scanId: plan.scanId, primaryContract: plan.primaryContract, primarySourcePath: plan.primarySourcePath, mode: plan.mode, members: [] };
      if (!group.members.some((member) => member.proposalId === input.proposalId && member.propertyName === property.name)) group.members.push({ proposalId: input.proposalId, hypothesisId: plan.hypothesisId, propertyName: property.name });
      groups.set(id, group);
    }
  }
  return [...groups.values()].map((group) => ({ ...group, members: group.members.sort((a, b) => a.proposalId.localeCompare(b.proposalId) || a.propertyName.localeCompare(b.propertyName)) })).sort((a, b) => a.id.localeCompare(b.id));
}
