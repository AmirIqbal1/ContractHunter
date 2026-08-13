import path from "node:path";
import { AnalysisContextBuilder, loadConfig } from "@contracthunter/core";
import { getDatabase, getScan, listInvestigations, listScanScanners } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const id = idSchema.safeParse((await context.params).id); if (!id.success) return NextResponse.json({ error: "Invalid scan identifier." }, { status: 400 });
  const config = loadConfig(); const database = getDatabase(); const scan = getScan(database, id.data); if (!scan) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  try {
    const scannerSummary = Object.fromEntries(listScanScanners(database, scan.id).map((scanner) => [scanner.scannerId, scanner.findingCount]));
    const manifest = new AnalysisContextBuilder({ maxSourceBytes: config.AI_MAX_SOURCE_BYTES, maxFiles: config.AI_MAX_FILES, maxFileBytes: config.AI_MAX_FILE_BYTES }).build(path.join(config.REPOSITORY_DIR, scan.id), listInvestigations(database, { scanId: scan.id }), scannerSummary).manifest;
    return NextResponse.json({ approximateInputBytes: manifest.approximateInputBytes, totalSourceBytes: manifest.totalSourceBytes, fileCount: manifest.files.length, omittedFileCount: manifest.omittedFileCount, truncated: manifest.truncated });
  } catch { return NextResponse.json({ error: "Analysis context is not available." }, { status: 409 }); }
}
