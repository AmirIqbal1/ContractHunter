import Link from "next/link";
import { notFound } from "next/navigation";
import { getDatabase, getScan } from "@contracthunter/db";
import { ProtocolMap } from "@/components/protocol-map";
import { loadProtocolMapForPage } from "@/lib/protocol-map-server";
import { parseSecurityMapView } from "@/lib/security-view-map";

export const dynamic = "force-dynamic";

export default async function ProtocolMapPage({ params, searchParams }: { params: Promise<{ id: string }>;
  searchParams?: Promise<{ node?: string; view?: string; mode?: string }> }) {
  const { id } = await params;
  const { node, view, mode } = await (searchParams ?? Promise.resolve({ node: undefined, view: undefined, mode: undefined }));
  const database = getDatabase();
  const scan = getScan(database, id);
  if (!scan) notFound();
  const { artifact, invalid } = loadProtocolMapForPage(database, id);
  return <>
    <header className="page-head"><div><div className="eyebrow">Hunt / Protocol Intelligence</div>
      <h1>Protocol Map</h1><p className="subhead">{scan.repositoryName} · static source-linked relationships</p></div>
      <div className="sh-actions"><Link className="button" href={`/hunts/${id}/start?mode=${mode === "researcher" ? "researcher" : "beginner"}`}>SHOW ME WHERE TO START</Link>
        <Link className="button secondary-button" href={`/hunts/${id}`}>← BACK TO HUNT</Link></div></header>
    {!artifact ? <div className="card pm-unavailable"><h2>{invalid ? "Protocol Map could not be loaded" : "Protocol Map unavailable"}</h2>
      <p className="muted">{invalid ? "The saved graph failed validation. The underlying scan remains available." :
        "This scan has no finalized static graph. Older scans are not backfilled; run a new scan to generate one."}</p>
      <Link className="muted-link" href={`/hunts/${id}`}>Return to hunt →</Link></div> :
      <ProtocolMap artifact={artifact} scanId={id} initialView={parseSecurityMapView(view)} initialMode={mode === "researcher" ? "researcher" : "beginner"} initialSelectedId={artifact.graph.nodes.some((item) =>
        item.id === node && ["contract", "interface", "library"].includes(item.kind)) ? node : null} />}
  </>;
}
