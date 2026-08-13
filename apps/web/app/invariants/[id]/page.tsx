import Link from "next/link";
import { notFound } from "next/navigation";
import { getDatabase, getInvariant, getProtocolAnalysis } from "@contracthunter/db";
import { SeverityBadge } from "@/components/badges";
import { InvariantStatusControl } from "@/components/invariant-status-control";

export const dynamic = "force-dynamic";
const parse = <T,>(value: string, fallback: T): T => { try { return JSON.parse(value) as T; } catch { return fallback; } };
type Evidence = { filePath: string; contract: string | null; functionName: string | null; startLine: number | null; endLine: number | null; valid?: boolean; validationError?: string | null };
export default async function InvariantPage({ params }: { params: Promise<{ id: string }> }) {
  const database = getDatabase(); const invariant = getInvariant(database, (await params).id); if (!invariant) notFound(); const analysis = getProtocolAnalysis(database, invariant.analysisId);
  const contracts = parse<string[]>(invariant.relatedContracts, []), functions = parse<string[]>(invariant.relatedFunctions, []), state = parse<string[]>(invariant.relatedState, []), evidence = parse<Evidence[]>(invariant.sourceEvidence, []);
  return <article className="article"><header className="page-head"><div><div className="eyebrow">Security invariant / {invariant.category}</div><h1>{invariant.title}</h1><p className="subhead">AI-proposed property from <Link className="muted-link" href={`/protocol-analyses/${invariant.analysisId}`}>{analysis?.protocolName ?? "protocol analysis"}</Link></p></div><SeverityBadge value={invariant.severityIfViolated} /></header>
    <section className="card"><dl className="details"><div className="detail"><dt>Impact if violated</dt><dd>{invariant.severityIfViolated}</dd></div><div className="detail"><dt>Evidence confidence</dt><dd>{invariant.confidence}%</dd></div><div className="detail"><dt>Testability</dt><dd>{invariant.testability}</dd></div><div className="detail"><dt>Status</dt><dd><InvariantStatusControl id={invariant.id} status={invariant.status} /></dd></div></dl></section>
    <section className="article-section"><h2>Description</h2><p>{invariant.description}</p></section><section className="article-section"><h2>Rationale</h2><p>{invariant.rationale}</p></section>
    <section className="article-section"><h2>Related protocol elements</h2><p><strong>Contracts:</strong> {contracts.join(", ") || "—"}<br /><strong>Functions:</strong> {functions.join(", ") || "—"}<br /><strong>State:</strong> {state.join(", ") || "—"}</p></section>
    <section className="article-section"><h2>Repository evidence</h2>{evidence.map((item, index) => <p className="mono" key={`${item.filePath}-${index}`}>{item.filePath}{item.startLine ? `:${item.startLine}${item.endLine && item.endLine !== item.startLine ? `–${item.endLine}` : ""}` : ""} · {item.contract ?? "—"}.{item.functionName ?? "—"} · <span className={item.valid === false ? "red" : "green"}>{item.valid === false ? `invalid: ${item.validationError}` : "validated"}</span></p>)}{!evidence.length && <p>No source evidence supplied.</p>}</section>
  </article>;
}
