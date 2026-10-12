import { notFound } from "next/navigation";
import { getDatabase, getFinding, getScan } from "@contracthunter/db";
import { FunctionExplorer } from "@/components/function-explorer";
import { readFunctionExplorer } from "@/lib/function-explorer-server";

export const dynamic = "force-dynamic";
const nodeId = /^pn:[a-f0-9]{64}$/;

export default async function FunctionExplorerPage({ params, searchParams }: {
  params: Promise<{ id: string; contractId: string; functionId: string }>;
  searchParams?: Promise<{ operation?: string; filter?: string; mode?: string }>;
}) {
  const { id, contractId, functionId } = await params;
  if (!nodeId.test(contractId) || !nodeId.test(functionId)) notFound();
  const database = getDatabase(), scan = getScan(database, id);
  if (!scan) notFound();
  let data: ReturnType<typeof readFunctionExplorer>;
  try { data = readFunctionExplorer(database, id, contractId, functionId); }
  catch { notFound(); }
  if (!data) notFound();
  const findings = data.model.findings.slice(0, 128).flatMap((findingId) => {
    const finding = getFinding(database, findingId);
    return finding?.scanId === id ? [finding] : [];
  }).map((item) => ({ id: item.id, title: item.title, source: item.source,
      detectorId: item.detectorId, status: item.status }));
  const state = await (searchParams ?? Promise.resolve({} as { operation?: string; filter?: string; mode?: string }));
  return <FunctionExplorer data={data} findings={findings} repositoryName={scan.repositoryName}
    initialOperation={data.model.operations.some((item) => item.id === state.operation) ? state.operation! : null}
    initialFilter={state.filter} initialMode={state.mode} />;
}
