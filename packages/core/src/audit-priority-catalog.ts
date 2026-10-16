/** Fixed educational copy. Keys are product terminology, not inferred contract descriptions. */
export const AUDIT_PRIORITY_CATALOG_VERSION = "contracthunter-beginner-concepts-v1" as const;
export const auditConcepts = {
  "external-entry-point": { term: "External entry point", meaning: "A public or external function callable from outside the contract.", why: "It is a place where outside input reaches contract code.", inspect: ["Inspect inputs and access checks."] },
  "state-read": { term: "State read", meaning: "Reads data stored by a contract.", why: "The value may affect a decision or calculation.", inspect: ["Trace where the value is written."] },
  "state-write": { term: "State write", meaning: "Changes data stored by a contract.", why: "Later calls may depend on the changed value.", inspect: ["Inspect authorization and ordering around external calls."] },
  "external-call": { term: "External call", meaning: "Calls code in another contract.", why: "Control can temporarily leave the current contract.", inspect: ["Inspect target selection and return handling.", "Inspect state changes around the call."] },
  "unresolved-external-call": { term: "Unresolved external call", meaning: "A call whose target cannot be proven statically.", why: "The destination may be selected at runtime.", inspect: ["Trace how the target is chosen."] },
  "low-level-call": { term: "Low-level call", meaning: "Uses a low-level EVM call operation.", why: "Return values and target behavior need careful review.", inspect: ["Inspect target, value and success handling."] },
  delegatecall: { term: "delegatecall", meaning: "Executes another contract's code using the current contract's storage.", why: "Target control and storage layout matter.", inspect: ["Inspect target selection, authorization and storage layout."] },
  "token-transfer": { term: "Token transfer-like operation", meaning: "Code calls a token transfer-like operation.", why: "Asset handling is important to understand even when the exact asset is unknown.", inspect: ["Inspect token identity, return handling and accounting."] },
  "native-value-transfer": { term: "Native value transfer", meaning: "A call carries native currency value.", why: "Value can leave the current execution context.", inspect: ["Inspect recipient selection and accounting."] },
  payable: { term: "payable", meaning: "A function can receive native currency.", why: "Value receipt may change the contract's balance.", inspect: ["Inspect value handling and refund paths."] },
  "owner-control": { term: "Owner control", meaning: "A proven ownership check protects a specific function.", why: "The protected operation may affect configuration or funds.", inspect: ["Inspect the exact guard and owner changes."] },
  "role-control": { term: "Role control", meaning: "A proven role relationship protects a specific function.", why: "The role's scope determines who can act.", inspect: ["Inspect role grants, revocations and guarded functions."] },
  "oracle-dependency": { term: "Oracle dependency", meaning: "Static evidence identifies an oracle-like value source.", why: "External values can influence calculations.", inspect: ["Inspect value source, freshness checks and consuming calculations."] },
  proxy: { term: "Proxy", meaning: "A proven proxy delegates behavior to implementation code.", why: "Implementation selection and storage layout matter.", inspect: ["Inspect implementation resolution and admin controls."] },
  implementation: { term: "Implementation", meaning: "Code used by a proven proxy relationship.", why: "Its behavior may run in the proxy's storage context.", inspect: ["Inspect storage compatibility and initialization."] },
  "upgrade-authority": { term: "Upgrade authority", meaning: "A proven control relationship affects an upgrade operation.", why: "Upgrades can change protocol behavior.", inspect: ["Inspect upgrade authorization and implementation validation."] },
  assembly: { term: "Assembly", meaning: "Inline assembly or Yul is present.", why: "Higher-level static interpretation may be incomplete.", inspect: ["Inspect low-level memory, storage and call behavior."] },
  finding: { term: "Finding", meaning: "ContractHunter attached a finding to an exact graph identity.", why: "It gives a concrete item to investigate.", inspect: ["Review the attached finding and its source evidence."] },
  "source-order": { term: "Source order", meaning: "Operations are compared by source position, not proven runtime path.", why: "Branches and loops can change actual execution order.", inspect: ["Inspect runtime paths and reentrancy protections."] },
  "review-cue": { term: "Review cue", meaning: "A deterministic fact that suggests a manual inspection target.", why: "It is not a vulnerability conclusion.", inspect: ["Check the cited source before drawing a conclusion."] },
  "core-protocol": { term: "Core protocol", meaning: "Repository Mapper classified this contract as core protocol code.", why: "It is likely central to the repository's architecture.", inspect: ["Confirm its role from source and call relationships."] },
  connectivity: { term: "Connectivity", meaning: "Other protocol components call or are called by this contract.", why: "Connected code can be important to understand together.", inspect: ["Inspect the exact caller and callee relationships."] },
  "callback-hook": { term: "Callback or hook", meaning: "Exact signature or interface evidence identifies a callback-like function.", why: "Another contract may invoke it during an interaction.", inspect: ["Inspect caller assumptions and state changes."] },
} as const;
export type AuditConceptKey = keyof typeof auditConcepts;

export const AUDIT_PRIORITY_RULESET_VERSION = "contracthunter-audit-priority-ruleset-v1" as const;
/** Maximum potential integer points per factor. Quantity buckets are implemented in the deriver. */
export const auditFactorRules = {
  "core-protocol": { max: 4, concept: "core-protocol" },
  "token-transfer": { max: 12, concept: "token-transfer" },
  "native-value-transfer": { max: 8, concept: "native-value-transfer" },
  "external-entry-points": { max: 9, concept: "external-entry-point" },
  "external-call": { max: 8, concept: "external-call" },
  "unresolved-external-call": { max: 9, concept: "unresolved-external-call" },
  "low-level-call": { max: 5, concept: "low-level-call" },
  "delegatecall": { max: 8, concept: "delegatecall" },
  "oracle-dependent": { max: 7, concept: "oracle-dependency" },
  "privileged-operation": { max: 6, concept: "role-control" },
  "owner-controlled": { max: 5, concept: "owner-control" },
  "role-controlled": { max: 5, concept: "role-control" },
  upgradeable: { max: 7, concept: "upgrade-authority" },
  proxy: { max: 6, concept: "proxy" },
  payable: { max: 4, concept: "payable" },
  "state-writing": { max: 5, concept: "state-write" },
  connectivity: { max: 4, concept: "connectivity" },
  "finding-linked": { max: 5, concept: "finding" },
  assembly: { max: 5, concept: "assembly" },
  callback: { max: 4, concept: "callback-hook" },
  "write-after-external-call-source-order": { max: 5, concept: "source-order" },
} as const satisfies Record<string, { max: number; concept: AuditConceptKey }>;
export type AuditFactorId = keyof typeof auditFactorRules;
