import Link from "next/link";
import { notFound } from "next/navigation";
import { TextDecoder } from "node:util";
import { getDatabase, getScan, getScanSource, readStaticProtocolGraph } from "@contracthunter/db";

export const dynamic = "force-dynamic";

export default async function SnapshotSourcePage({ params, searchParams }: {
  params: Promise<{ id: string }>; searchParams: Promise<{ unit?: string; line?: string }>;
}) {
  const { id } = await params;
  const { unit, line } = await searchParams;
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  const requestedLine = Number(line ?? "1");
  if (!unit || unit.length > 500 || !Number.isSafeInteger(requestedLine) || requestedLine < 1) notFound();
  let artifact: ReturnType<typeof readStaticProtocolGraph> = null;
  try { artifact = readStaticProtocolGraph(database, id); } catch { notFound(); }
  if (!artifact || !artifact.graph.sourceUnits.some((source) => source.sourceUnitName === unit)) notFound();
  const source = getScanSource(database, id, unit);
  let lines: string[] | null = null;
  if (source.available) {
    try { lines = new TextDecoder("utf-8", { fatal: true }).decode(source.rawBytes).split(/\r?\n/); } catch { lines = null; }
  }
  const start = lines ? Math.max(1, requestedLine - 30) : 1;
  const end = lines ? Math.min(lines.length, requestedLine + 30) : 0;
  return <>
    <header className="page-head"><div><div className="eyebrow">Hunt / Source snapshot</div><h1>{unit}</h1>
      <p className="subhead">{scan.repositoryName} · requested line {requestedLine}</p></div>
      <Link className="button secondary-button" href={`/hunts/${id}/protocol-map`}>← PROTOCOL MAP</Link></header>
    {lines ? <div className="card pm-source" aria-label="Immutable scan source excerpt">
      {lines.slice(start - 1, end).map((text, index) => <div key={start + index}
        className={start + index === requestedLine ? "pm-source-highlight" : ""}>
        <span aria-label={`Line ${start + index}`}>{start + index}</span><code>{text || " "}</code></div>)}</div> :
      <div className="card pm-unavailable"><h2>Snapshot source unavailable</h2>
        <p className="muted">This graph retains a canonical source identity, but this scan has no readable immutable source snapshot. No mutable checkout content was substituted.</p></div>}
  </>;
}
