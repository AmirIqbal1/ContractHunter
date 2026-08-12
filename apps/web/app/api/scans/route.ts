import { createScanInputSchema, validateGitHubUrl, validateGitRef } from "@contracthunter/core";
import { createScan, getDatabase, listScans } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { apiError } from "@/lib/api";
import { getJobRunner } from "@/lib/runner";

export const runtime = "nodejs";

export async function GET() {
  return NextResponse.json({ scans: listScans(getDatabase()) });
}

export async function POST(request: Request) {
  try {
    const input = createScanInputSchema.parse(await request.json());
    const repository = validateGitHubUrl(input.repositoryUrl);
    const requestedRef = validateGitRef(input.requestedRef);
    const runner = getJobRunner();
    const scan = createScan(getDatabase(), { ...input, requestedRef, repositoryUrl: repository.url, repositoryName: repository.name });
    runner.enqueue(scan.id);
    return NextResponse.json({ scan }, { status: 202 });
  } catch (error) {
    return apiError(error, "Unable to create scan.");
  }
}
