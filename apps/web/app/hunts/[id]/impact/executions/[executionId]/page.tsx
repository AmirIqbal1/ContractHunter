import Link from "next/link";
import { notFound } from "next/navigation";
import { getDatabase, getScan, readStaticProtocolGraph } from "@contracthunter/db";
import { ObservedExecution } from "@/components/observed-execution";
import { idSchema } from "@/lib/api";
import { loadImpactOverlay } from "@/lib/impact-overlay-server";

export const dynamic = "force-dynamic";
export default async function ImpactExecutionPage({ params, searchParams }: {
  params: Promise<{ id: string; executionId: string }>;
  searchParams?: Promise<{ tx?: string; call?: string; state?: string; mode?: string }>;
}) {
  const { id, executionId } = await params;
  if (!idSchema.safeParse(id).success || !idSchema.safeParse(executionId).success) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  let overlay: ReturnType<typeof loadImpactOverlay> = null;
  let artifact: ReturnType<typeof readStaticProtocolGraph> = null;
  try { overlay = loadImpactOverlay(database, id, executionId); artifact = readStaticProtocolGraph(database, id); }
  catch { return <main className="card"><h1>Observed execution unavailable</h1><p>Persisted evidence failed validation.</p></main>; }
  if (!overlay) notFound();
  const query = await (searchParams ?? Promise.resolve({} as { tx?: string; call?: string; state?: string; mode?: string }));
  const tx = Number(query.tx);
  const path = `/hunts/${encodeURIComponent(id)}/investigation-paths/${overlay.subject.type}/${encodeURIComponent(overlay.subject.id)}?execution=${encodeURIComponent(executionId)}`;
  return <main className="io-page"><nav className="ce-breadcrumb" aria-label="Breadcrumb"><Link href={`/hunts/${encodeURIComponent(id)}`}>{scan.repositoryName}</Link><span>/</span><strong>Observed Local Execution</strong></nav>
    <header className="page-head"><div><div className="eyebrow">LOCAL FORK · IMPACT LAB</div><h1>Observed Local Execution</h1><p className="subhead">Exact reviewed PoC execution · {executionId}</p></div></header>
    <div className="ip-actions">{overlay.investigationPathResultId && <Link href={`${path}&view=compare`}>Compare With Investigation Path</Link>}
      {overlay.protocolGraphId && <Link href={`/hunts/${encodeURIComponent(id)}/protocol-map?execution=${encodeURIComponent(executionId)}&observed=1`}>Show on Protocol Map</Link>}
      {overlay.capabilities.traceAvailable && <a href="#observed-execution">View Observed Execution</a>}
      {overlay.capabilities.statePreAvailable && <a href="#observed-state">View State Changes</a>}</div>
    <nav className="sh-mode" aria-label="Display mode"><Link aria-current={query.mode !== "researcher" ? "page" : undefined} href={`?mode=beginner`}>Beginner</Link>
      <Link aria-current={query.mode === "researcher" ? "page" : undefined} href={`?mode=researcher`}>Researcher</Link></nav>
    <ObservedExecution overlay={overlay} artifact={artifact} researcher={query.mode === "researcher"}
      initialTx={Number.isInteger(tx) && tx >= 0 ? tx : 0} initialCall={query.call} initialState={query.state} />
  </main>;
}
