/** Conservative source-signature validation shared by historical verification and executable invariants. */
export type SolidityArgumentKind = "address" | "uint" | "bool";
export type SourceFunctionUse = { kind: "call" | "read-uint" | "read-address"; functionName: string; argumentKinds: SolidityArgumentKind[] };
export class SolidityFunctionValidationError extends Error {
  constructor(readonly reason: string) { super(reason); this.name = "SolidityFunctionValidationError"; }
}
const reject = (reason: string): never => { throw new SolidityFunctionValidationError(reason); };
const escape = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
export const solidityStructure = (value: string) => value.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\r\n]*/g, " ").replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, "");
const signatureKind = (parameter: string): SolidityArgumentKind | null => {
  const tokens = parameter.trim().split(/\s+/).filter(Boolean);
  if (tokens.some((token) => ["calldata", "memory", "storage"].includes(token))) return null;
  if (tokens[0] === "address") return "address";
  if (tokens[0] === "uint" || tokens[0] === "uint256") return "uint";
  if (tokens[0] === "bool") return "bool";
  return null;
};
const parameterKinds = (parameters: string): SolidityArgumentKind[] | null => {
  if (!parameters.trim()) return [];
  const result = parameters.split(",").map(signatureKind);
  return result.some((kind) => kind === null) ? null : result as SolidityArgumentKind[];
};
const returnKind = (suffix: string): SolidityArgumentKind | null => {
  const match = /\breturns\s*\(([^)]*)\)/.exec(suffix);
  if (!match) return null;
  const kinds = parameterKinds(match[1]);
  return kinds?.length === 1 ? kinds[0] : null;
};
export function validateSolidityFunctionUses(primarySource: string, sources: string[], primaryContract: string, uses: SourceFunctionUse[], relevantFunctions: string[] = [], primaryOnly = false): void {
  const primary = solidityStructure(primarySource);
  let combined = sources.map(solidityStructure).join("\n");
  if (!new RegExp(`\\b(?:contract|library)\\s+${escape(primaryContract)}\\b`).test(primary)) reject("primary_contract_not_found");
  if (primaryOnly) {
    const match = new RegExp(`\\b(?:contract|library)\\s+${escape(primaryContract)}\\b[^\\{]*\\{`).exec(primary);
    if (!match) throw new SolidityFunctionValidationError("primary_contract_not_found");
    const begin = match.index + match[0].length; let depth = 1; let end = begin;
    while (end < primary.length && depth > 0) { if (primary[end] === "{") depth++; if (primary[end] === "}") depth--; end++; }
    if (depth !== 0) reject("primary_contract_not_found");
    combined = primary.slice(begin, end - 1);
  }
  if ([...(primaryOnly ? combined : primary).matchAll(/\bconstructor\s*\(([^)]*)\)/g)].some((match) => match[1].trim())) reject("constructor_arguments_unsupported");
  const hasExplicitFunction = (name: string) => new RegExp(`\\bfunction\\s+${escape(name)}\\s*\\(`).test(combined);
  const hasPublicGetter = (kind: "uint" | "address", name: string) => {
    const type = kind === "uint" ? "uint(?:256)?" : "address(?:\\s+payable)?";
    return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && [...combined.matchAll(new RegExp(`\\b${type}\\s+([^;{}]+);`, "g"))].some((match) => {
      const declaration = match[1].split("=", 1)[0].trim().split(/\s+/).filter(Boolean);
      return declaration.includes("public") && declaration.at(-1) === name;
    });
  };
  for (const name of relevantFunctions) if (!hasExplicitFunction(name) && !hasPublicGetter("uint", name) && !hasPublicGetter("address", name)) reject("relevant_function_not_found");
  for (const use of uses) {
    const signatures = [...combined.matchAll(new RegExp(`\\bfunction\\s+${escape(use.functionName)}\\s*\\(([^)]*)\\)([^;{]*)`, "g"))];
    if (primaryOnly && signatures.some((match) => !/\b(?:public|external)\b/.test(match[2]))) reject("function_not_public");
    if (primaryOnly && signatures.length > 1) reject("ambiguous_function_signature");
    const supported = signatures.map((match) => ({ match, kinds: parameterKinds(match[1]) }));
    const matching = supported.filter(({ kinds }) => kinds !== null && kinds.length === use.argumentKinds.length && kinds.every((kind, i) => kind === use.argumentKinds[i]));
    const getterKind = use.kind === "read-uint" ? "uint" : use.kind === "read-address" ? "address" : null;
    const getters = getterKind ? Number(hasPublicGetter(getterKind, use.functionName)) : 0;
    const incompatible = use.kind === "read-uint" ? Number(hasPublicGetter("address", use.functionName)) : use.kind === "read-address" ? Number(hasPublicGetter("uint", use.functionName)) : 0;
    if (!signatures.length && !getters && incompatible) reject("unsupported_return_type");
    if (!signatures.length && !getters) reject("function_not_found");
    if (supported.some(({ kinds }) => kinds === null) && !matching.length && !getters) reject("unsupported_parameter_type");
    if (!matching.length && !getters) reject("argument_shape_mismatch");
    if (use.kind === "call") { if (matching.length !== 1) reject("ambiguous_function_signature"); continue; }
    if (primaryOnly && signatures.some((match) => !/\b(?:view|pure)\b/.test(match[2]))) reject("getter_not_read_only");
    const expected = use.kind === "read-address" ? "address" : "uint";
    const compatible = getters + matching.filter(({ match }) => returnKind(match[2]) === expected).length;
    if (!compatible) reject("unsupported_return_type");
    if (compatible !== 1) reject("ambiguous_function_signature");
  }
}
