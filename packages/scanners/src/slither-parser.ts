import { createHash } from "node:crypto";
import path from "node:path";
import { z } from "zod";
import type { NewFinding, Severity } from "@contracthunter/core";

const sourceMappingSchema = z.object({
  filename_relative: z.string().optional(),
  filename_short: z.string().optional(),
  lines: z.array(z.number().int().positive()).optional(),
  starting_column: z.number().int().optional(),
  ending_column: z.number().int().optional(),
}).passthrough();

const elementSchema = z.object({
  type: z.string().optional(),
  name: z.string().optional(),
  source_mapping: sourceMappingSchema.optional(),
  type_specific_fields: z.object({
    parent: z.object({ name: z.string().optional() }).passthrough().optional(),
  }).passthrough().optional(),
}).passthrough();

export const slitherDetectorSchema = z.object({
  check: z.string().min(1),
  impact: z.string().optional().default("Informational"),
  confidence: z.string().optional().default("Unknown"),
  description: z.string().optional().default(""),
  elements: z.array(elementSchema).optional().default([]),
  markdown: z.string().optional(),
  first_markdown_element: z.string().optional(),
  id: z.string().optional(),
  wiki: z.string().url().optional(),
}).passthrough();

export const slitherOutputSchema = z.object({
  success: z.boolean(),
  error: z.unknown().optional(),
  results: z.object({ detectors: z.array(slitherDetectorSchema).optional().default([]) }).passthrough().optional(),
}).passthrough();

export type SlitherOutput = z.infer<typeof slitherOutputSchema>;
export type SlitherDetector = z.infer<typeof slitherDetectorSchema>;

export class SlitherParseError extends Error {
  constructor(message: string) { super(message); this.name = "SlitherParseError"; }
}

export function parseSlitherJson(raw: string): SlitherOutput {
  let decoded: unknown;
  try { decoded = JSON.parse(raw); }
  catch { throw new SlitherParseError("Slither returned malformed JSON."); }
  const parsed = slitherOutputSchema.safeParse(decoded);
  if (!parsed.success) throw new SlitherParseError("Slither returned an unsupported JSON response.");
  if (!parsed.data.success) {
    const detail = typeof parsed.data.error === "string" ? parsed.data.error : "Slither reported an unsuccessful analysis.";
    throw new SlitherParseError(detail);
  }
  return parsed.data;
}

export function mapSlitherSeverity(impact: string): Severity {
  switch (impact.toLowerCase()) {
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    case "informational": return "informational";
    default: return "informational";
  }
}

export function mapSlitherConfidence(confidence: string): number {
  switch (confidence.toLowerCase()) {
    case "high": return 90;
    case "medium": return 70;
    case "low": return 50;
    default: return 40;
  }
}

export function detectorTitle(detectorId: string): string {
  const acronyms = new Set(["eth", "erc", "nft", "dos"]);
  return detectorId.split(/[-_.]+/).filter(Boolean).map((word) => acronyms.has(word.toLowerCase()) ? word.toUpperCase() : `${word.charAt(0).toUpperCase()}${word.slice(1)}`).join(" ");
}

function safeRelativeFile(repositoryPath: string, filename: string | undefined): string | null {
  if (!filename) return null;
  const root = path.resolve(repositoryPath);
  const candidate = path.isAbsolute(filename) ? path.resolve(filename) : path.resolve(root, filename);
  if (candidate !== root && !candidate.startsWith(`${root}${path.sep}`)) return null;
  const relative = path.relative(root, candidate);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative.split(path.sep).join("/") : null;
}

type SourceMapping = {
  filenameRelative?: string;
  filenameShort?: string;
  lines: number[];
};

function sourceMappingOf(element: unknown): SourceMapping | null {
  if (!element || typeof element !== "object") return null;
  const mapping = (element as Record<string, unknown>).source_mapping;
  if (!mapping || typeof mapping !== "object") return null;
  const value = mapping as Record<string, unknown>;
  return {
    filenameRelative: typeof value.filename_relative === "string" ? value.filename_relative : undefined,
    filenameShort: typeof value.filename_short === "string" ? value.filename_short : undefined,
    lines: Array.isArray(value.lines)
      ? value.lines.filter((line): line is number => Number.isInteger(line) && Number(line) > 0)
      : [],
  };
}

function directParentName(element: unknown): string | null {
  if (!element || typeof element !== "object") return null;
  const fields = (element as Record<string, unknown>).type_specific_fields;
  if (!fields || typeof fields !== "object") return null;
  const parent = (fields as Record<string, unknown>).parent;
  if (!parent || typeof parent !== "object") return null;
  const name = (parent as Record<string, unknown>).name;
  return typeof name === "string" ? name : null;
}

function location(detector: SlitherDetector, repositoryPath: string) {
  const ancestry = detector.elements.flatMap((element) => {
    const chain: Array<Record<string, unknown>> = [element];
    let current: unknown = element;
    for (let depth = 0; depth < 8; depth++) {
      if (!current || typeof current !== "object") break;
      const fields = (current as Record<string, unknown>).type_specific_fields;
      if (!fields || typeof fields !== "object") break;
      const parent = (fields as Record<string, unknown>).parent;
      if (!parent || typeof parent !== "object") break;
      chain.push(parent as Record<string, unknown>);
      current = parent;
    }
    return chain;
  });
  const functionElement = ancestry.find((element) => ["function", "modifier"].includes(typeof element.type === "string" ? element.type.toLowerCase() : ""));
  const contractElement = ancestry.find((element) => (typeof element.type === "string" ? element.type.toLowerCase() : "") === "contract");
  const located = [functionElement, ...detector.elements].find((element) => {
    const mapping = sourceMappingOf(element);
    return mapping?.filenameRelative || mapping?.filenameShort;
  });
  const mapping = sourceMappingOf(located);
  const lines = mapping?.lines ?? [];
  return {
    contract: typeof contractElement?.name === "string" ? contractElement.name : directParentName(functionElement),
    functionName: typeof functionElement?.name === "string" ? functionElement.name : null,
    filePath: safeRelativeFile(repositoryPath, mapping?.filenameRelative ?? mapping?.filenameShort),
    startLine: lines.length ? Math.min(...lines) : null,
    endLine: lines.length ? Math.max(...lines) : null,
  };
}

export function normaliseSlitherFindings(output: SlitherOutput, scanId: string, repositoryPath: string): NewFinding[] {
  const unique = new Map<string, NewFinding>();
  for (const detector of output.results?.detectors ?? []) {
    const place = location(detector, repositoryPath);
    const fingerprint = createHash("sha256").update(JSON.stringify([
      scanId, "slither", detector.check, place.filePath, place.startLine, place.endLine, place.contract, place.functionName,
    ])).digest("hex");
    if (unique.has(fingerprint)) continue;
    const description = (detector.description.trim() || `Slither detector: ${detector.check}`).split(`${path.resolve(repositoryPath)}${path.sep}`).join("");
    const reference = detector.wiki ? `\nReference: ${detector.wiki}` : "";
    unique.set(fingerprint, {
      title: detectorTitle(detector.check), severity: mapSlitherSeverity(detector.impact), confidence: mapSlitherConfidence(detector.confidence),
      source: "slither", detectorId: detector.check, fingerprint, ...place,
      rootCause: description, attackScenario: "", impact: "", evidence: `${description}${reference}`,
      status: "candidate",
    });
  }
  return [...unique.values()];
}
