import type { BountyReport, ReportBlock } from "@contracthunter/core";

function Block({ value }: { value: ReportBlock }) {
  if (value.kind === "text") return <p style={{ whiteSpace: "pre-wrap" }}>{value.text}</p>;
  if (value.kind === "list") return <ul>{value.items.map((item, i) => <li key={i}>{item}</li>)}</ul>;
  if (value.kind === "code") return <pre className="mono bounty-code"><code>{value.source}</code></pre>;
  return <div className="af-table-wrap"><table><thead><tr>{value.columns.map((column, i) => <th scope="col" key={i}>{column}</th>)}</tr></thead>
    <tbody>{value.rows.map((row, i) => <tr key={i}>{row.map((cell, j) => <td key={j} className="bounty-cell">{cell}</td>)}</tr>)}</tbody></table></div>;
}

export function BountyReportPaper({ value }: { value: BountyReport }) {
  return <article className="bounty-paper"><div className="eyebrow">{value.status === "draft" ? "DRAFT BUG-BOUNTY REPORT" : "FINALIZED BUG-BOUNTY REPORT"}</div>
    <h1>{value.fields.title}</h1>
    <p className="mono bounty-print-identity">Report ID: {value.reportId}<br />Report content hash: {value.contentHash}<br />Evidence Package ID: {value.evidencePackageId}<br />Package content hash: {value.evidencePackageContentHash}<br />Manifest hash: {value.evidenceManifestHash}</p>
    {value.sections.map((section) => <section key={section.id} className="bounty-section"><h2>{section.title}</h2>
      {section.blocks.map((block, i) => <Block key={i} value={block} />)}</section>)}
  </article>;
}
