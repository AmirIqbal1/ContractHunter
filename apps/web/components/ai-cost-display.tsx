import { aggregateRecordedAICost, formatAICost } from "@contracthunter/core";

export function RecordedAICost({ costUsd }: { costUsd: number | null }) {
  if (costUsd === null) return null;
  return <div className="hint" style={{ marginTop: 10 }}>Estimated API cost from recorded token usage: <strong>{formatAICost(costUsd)}</strong>. Estimate using configured token prices — not an official invoice.</div>;
}

export function AIUsageSummary({ protocolCostUsd, reviewCostUsd }: { protocolCostUsd: number | null; reviewCostUsd: number | null }) {
  const total = aggregateRecordedAICost([protocolCostUsd, reviewCostUsd]);
  if (total === null) return null;
  return <section className="section"><div className="section-head"><h2>AI usage this hunt</h2></div><div className="card"><dl className="details">
    {protocolCostUsd !== null && <div className="detail"><dt>Protocol analysis</dt><dd>{formatAICost(protocolCostUsd)}</dd></div>}
    {reviewCostUsd !== null && <div className="detail"><dt>Security review</dt><dd>{formatAICost(reviewCostUsd)}</dd></div>}
    <div className="detail"><dt>Recorded AI cost</dt><dd><strong>{formatAICost(total)}</strong></dd></div>
  </dl><div className="hint" style={{ marginTop: 12 }}>Estimated from recorded token usage and configured prices; not an official invoice.</div></div></section>;
}
