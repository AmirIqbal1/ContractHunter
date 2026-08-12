import { z } from "zod";

export const scanStatuses = ["queued", "cloning", "detecting", "scanning", "completed", "failed"] as const;
export const frameworks = ["foundry", "hardhat", "unknown"] as const;
export const scanDepths = ["quick", "deep", "maximum"] as const;
export const findingStatuses = ["candidate", "investigating", "verified", "rejected"] as const;
export const severities = ["critical", "high", "medium", "low", "informational"] as const;

export type ScanStatus = (typeof scanStatuses)[number];
export type Framework = (typeof frameworks)[number];
export type ScanDepth = (typeof scanDepths)[number];
export type FindingStatus = (typeof findingStatuses)[number];
export type Severity = (typeof severities)[number];

export const scanSchema = z.object({
  id: z.string().uuid(),
  repositoryUrl: z.string().url(),
  repositoryName: z.string().min(1),
  requestedRef: z.string().nullable(),
  resolvedCommit: z.string().regex(/^[a-f0-9]{40}$/).nullable(),
  status: z.enum(scanStatuses),
  framework: z.enum(frameworks),
  depth: z.enum(scanDepths),
  createdAt: z.date(),
  startedAt: z.date().nullable(),
  completedAt: z.date().nullable(),
  error: z.string().nullable(),
});

export const findingSchema = z.object({
  id: z.string().uuid(),
  scanId: z.string().uuid(),
  title: z.string().min(1).max(200),
  severity: z.enum(severities),
  confidence: z.number().min(0).max(100),
  source: z.string().min(1).max(100),
  contract: z.string().max(200).nullable(),
  functionName: z.string().max(200).nullable(),
  filePath: z.string().max(1000).nullable(),
  startLine: z.number().int().positive().nullable(),
  endLine: z.number().int().positive().nullable(),
  rootCause: z.string().min(1),
  attackScenario: z.string().min(1),
  impact: z.string().min(1),
  evidence: z.string().min(1),
  status: z.enum(findingStatuses),
  createdAt: z.date(),
}).refine((finding) => !finding.startLine || !finding.endLine || finding.endLine >= finding.startLine, {
  message: "endLine must be greater than or equal to startLine",
  path: ["endLine"],
});

export type Scan = z.infer<typeof scanSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type NewFinding = Omit<Finding, "id" | "scanId" | "createdAt">;

export const createScanInputSchema = z.object({
  repositoryUrl: z.string().trim().min(1),
  requestedRef: z.string().trim().max(200).optional().transform((value) => value || undefined),
  depth: z.enum(scanDepths).default("quick"),
});

export type CreateScanInput = z.infer<typeof createScanInputSchema>;

export interface ScanContext {
  scan: Scan;
  repositoryPath: string;
}

export interface ScannerResult {
  scannerId: string;
  findings: NewFinding[];
  warnings: string[];
}

export interface Scanner {
  id: string;
  name: string;
  isAvailable(): Promise<boolean>;
  scan(context: ScanContext): Promise<ScannerResult>;
}
