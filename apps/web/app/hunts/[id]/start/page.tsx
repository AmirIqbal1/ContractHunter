import Link from "next/link";
import { notFound } from "next/navigation";
import { deriveAuditPriorityFromArtifact } from "@contracthunter/core";
import type { AuditPriorityResult } from "@contracthunter/core";
import { getDatabase, getScan, readRepositoryMap, readStaticProtocolGraph } from "@contracthunter/db";
import { StartHere } from "@/components/start-here";

export const dynamic = "force-dynamic";

export default async function StartHerePage({ params, searchParams }: {
  params: Promise<{ id: string }>;
  searchParams?: Promise<{ mode?: string }>;
}) {
  const { id } = await params;
  const database = getDatabase();
  const scan = getScan(database, id);
  if (!scan) notFound();
  const mode = (await searchParams)?.mode === "researcher" ? "researcher" : "beginner";
  let result: AuditPriorityResult | null = null;
  let failed = false;
  try {
    const artifact = readStaticProtocolGraph(database, id);
    if (artifact) result = deriveAuditPriorityFromArtifact(artifact, readRepositoryMap(database, id));
  } catch { failed = true; }
  if (result) return <StartHere result={result} repositoryName={scan.repositoryName} initialMode={mode} />;
  if (failed) return <main><header className="page-head"><div><div className="eyebrow">Protocol Intelligence</div><h1>Start Here unavailable</h1></div></header>
    <p role="alert" className="card">The saved protocol analysis could not be loaded. Other scan results remain available.</p>
    <Link className="muted-link" href={`/hunts/${encodeURIComponent(id)}/protocol-map`}>Open Protocol Map →</Link></main>;
  return <main><header className="page-head"><div><div className="eyebrow">Protocol Intelligence</div><h1>Start Here unavailable</h1></div></header>
    <p className="card">This scan has no finalized static ProtocolGraph. Historical scans are not backfilled.</p>
    <Link className="muted-link" href={`/hunts/${encodeURIComponent(id)}`}>Back to hunt →</Link></main>;
}
