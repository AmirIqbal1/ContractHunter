import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import type { SourceEvidence, ValidatedEvidence } from "./ai-domain";

export function validateEvidence(repositoryPath: string, evidence: SourceEvidence): ValidatedEvidence {
  if (path.isAbsolute(evidence.filePath) || evidence.filePath.includes("\0") || evidence.filePath.split(/[\\/]/).includes("..")) return { ...evidence, valid: false, validationError: "Unsafe source path" };
  const root = realpathSync(repositoryPath);
  const absolute = path.resolve(root, evidence.filePath);
  if (!absolute.startsWith(`${root}${path.sep}`) || !existsSync(absolute)) return { ...evidence, valid: false, validationError: "Source file does not exist" };
  let real: string;
  try { real = realpathSync(absolute); } catch { return { ...evidence, valid: false, validationError: "Source file is unavailable" }; }
  if (!real.startsWith(`${root}${path.sep}`)) return { ...evidence, valid: false, validationError: "Source path escapes repository" };
  const source = readFileSync(real, "utf8");
  const lines = source.split(/\r?\n/).length;
  if ((evidence.startLine && evidence.startLine > lines) || (evidence.endLine && evidence.endLine > lines) || (evidence.startLine && evidence.endLine && evidence.endLine < evidence.startLine)) return { ...evidence, valid: false, validationError: "Invalid source line range" };
  if (evidence.contract && !new RegExp(`\\b(?:contract|interface|library)\\s+${escapeRegExp(evidence.contract)}\\b`).test(source)) return { ...evidence, valid: false, validationError: "Contract not found in source file" };
  const simpleFunction = evidence.functionName?.split("(")[0];
  if (simpleFunction && !new RegExp(`\\bfunction\\s+${escapeRegExp(simpleFunction)}\\b`).test(source)) return { ...evidence, valid: false, validationError: "Function not found in source file" };
  return { ...evidence, valid: true, validationError: null };
}

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
