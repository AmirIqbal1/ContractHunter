import { createHash } from "node:crypto";
import { existsSync, realpathSync } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { NewFinding, Severity } from "@contracthunter/core";

const instanceSchema = z.object({
  contract_path: z.string().optional(),
  line_no: z.number().int().positive().optional(),
  end_line: z.number().int().positive().optional(),
  contract_name: z.string().optional(),
  function_name: z.string().optional(),
  src: z.string().optional(),
  src_char: z.string().optional(),
}).passthrough();

const issueSchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  detector_name: z.string().optional(),
  instances: z.array(instanceSchema).optional().default([]),
  references: z.array(z.string()).optional(),
  reference: z.string().optional(),
  wiki_url: z.string().optional(),
}).passthrough();

const issueGroupSchema = z.object({ issues: z.array(issueSchema).optional().default([]) }).passthrough();

export const aderynReportSchema = z.object({
  high_issues: issueGroupSchema.optional(),
  medium_issues: issueGroupSchema.optional(),
  low_issues: issueGroupSchema.optional(),
  informational_issues: issueGroupSchema.optional(),
  info_issues: issueGroupSchema.optional(),
  issue_count: z.record(z.string(), z.number()).optional(),
}).passthrough();

export type AderynReport = z.infer<typeof aderynReportSchema>;
type AderynIssue = z.infer<typeof issueSchema>;

export class AderynParseError extends Error {
  constructor(message: string) { super(message); this.name = "AderynParseError"; }
}

export function parseAderynJson(raw: string): AderynReport {
  let decoded: unknown;
  try { decoded = JSON.parse(raw); }
  catch { throw new AderynParseError("Aderyn returned malformed JSON."); }
  const parsed = aderynReportSchema.safeParse(decoded);
  if (!parsed.success) throw new AderynParseError("Aderyn returned an unsupported JSON report.");
  return parsed.data;
}

export function mapAderynSeverity(value: string): Severity {
  switch (value.toLowerCase()) {
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    case "informational":
    case "info": return "informational";
    default: return "informational";
  }
}

function safeRelativeSource(repositoryPath: string, filename: string | undefined): string | null {
  if (!filename || path.isAbsolute(filename) || filename.includes("\0")) return null;
  const root = path.resolve(repositoryPath);
  const candidate = path.resolve(root, filename);
  if (candidate === root || !candidate.startsWith(`${root}${path.sep}`)) return null;
  if (existsSync(candidate)) {
    try {
      const realRoot = realpathSync(root);
      const realCandidate = realpathSync(candidate);
      if (realCandidate === realRoot || !realCandidate.startsWith(`${realRoot}${path.sep}`)) return null;
    } catch { return null; }
  }
  const relative = path.relative(root, candidate);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative.split(path.sep).join("/") : null;
}

function readableTitle(issue: AderynIssue): string {
  if (issue.title?.trim()) return issue.title.trim().slice(0, 200);
  const detector = issue.detector_name?.trim() || "aderyn-finding";
  return detector.split(/[-_.]+/).filter(Boolean).map((word) => `${word[0]?.toUpperCase() ?? ""}${word.slice(1)}`).join(" ").slice(0, 200);
}

function references(issue: AderynIssue): string[] {
  return [...new Set([...(issue.references ?? []), issue.reference, issue.wiki_url].filter((value): value is string => typeof value === "string" && /^https:\/\/[^\s]+$/i.test(value)))];
}

export function normaliseAderynFindings(report: AderynReport, scanId: string, repositoryPath: string): NewFinding[] {
  const groups: Array<[string, AderynIssue[]]> = [
    ["high", report.high_issues?.issues ?? []],
    ["medium", report.medium_issues?.issues ?? []],
    ["low", report.low_issues?.issues ?? []],
    ["informational", [...(report.informational_issues?.issues ?? []), ...(report.info_issues?.issues ?? [])]],
  ];
  const findings = new Map<string, NewFinding>();
  for (const [severityName, issues] of groups) {
    for (const issue of issues) {
      const detectorId = issue.detector_name?.trim().slice(0, 200) || "aderyn-finding";
      const instances = issue.instances.length ? issue.instances : [{}];
      for (const instance of instances) {
        const filePath = safeRelativeSource(repositoryPath, instance.contract_path);
        const startLine = instance.line_no ?? null;
        const endLine = instance.end_line && (!startLine || instance.end_line >= startLine) ? instance.end_line : startLine;
        const contract = instance.contract_name?.trim().slice(0, 200) || null;
        const functionName = instance.function_name?.trim().slice(0, 200) || null;
        const fingerprint = createHash("sha256").update(JSON.stringify([scanId, "aderyn", detectorId, filePath, startLine, endLine, contract, functionName])).digest("hex");
        if (findings.has(fingerprint)) continue;
        const description = issue.description?.trim() || `Aderyn detector: ${detectorId}`;
        const referenceText = references(issue).map((reference) => `Reference: ${reference}`).join("\n");
        const sourceEvidence = [instance.src ? `Source range: ${instance.src}` : "", referenceText].filter(Boolean).join("\n");
        findings.set(fingerprint, {
          title: readableTitle(issue),
          severity: mapAderynSeverity(severityName),
          confidence: 40,
          source: "aderyn",
          detectorId,
          fingerprint,
          contract,
          functionName,
          filePath,
          startLine,
          endLine,
          rootCause: description.slice(0, 10_000),
          attackScenario: "",
          impact: "",
          evidence: (sourceEvidence || description).slice(0, 10_000),
          status: "candidate",
        });
      }
    }
  }
  return [...findings.values()];
}
