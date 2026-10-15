import { canonicalEvidenceJson, evidenceHash, verifyEvidencePackageIntegrity, type EvidencePackage } from "./evidence-package";

export const BOUNTY_REPORT_SCHEMA = "contracthunter-bounty-report-v1" as const;
export const BOUNTY_REPORT_RULESET = "contracthunter-bounty-report-ruleset-v1" as const;
export const BOUNTY_REPORT_FIELD_LIMITS = { title: 200, summary: 4096, impactStatement: 8192,
  reproductionNote: 8192, additionalContext: 8192 } as const;
export type BountyReportFields = { title: string; summary: string; impactStatement: string;
  reproductionNote: string; additionalContext: string };
export type ReportBlock = { kind: "text"; text: string } | { kind: "list"; items: string[] } |
  { kind: "table"; columns: string[]; rows: string[][] } | { kind: "code"; language: string; source: string };
export type ReportSection = { id: string; title: string; blocks: ReportBlock[] };
export type BountyReport = { schema: typeof BOUNTY_REPORT_SCHEMA; rulesetVersion: typeof BOUNTY_REPORT_RULESET;
  reportId: string; revisionOf: string | null; status: "draft" | "finalized";
  evidencePackageId: string; evidencePackageContentHash: string; evidenceManifestHash: string;
  packageCompleteness: EvidencePackage["completeness"]; capabilities: EvidencePackage["capabilities"];
  fields: BountyReportFields; sections: ReportSection[]; createdAt: number; finalizedAt: number | null;
  contentHash: string };

const sensitive = /(?:\b(?:https?|wss?|file):\/\/[^\s"']+|\/(?:home|root|tmp|Users|mnt|opt|etc|run|srv|private|usr\/local|var\/run|workspace|app)\/[^\s"']+|[A-Za-z]:\\[^\s"']+|docker\.sock|(?:private[_ -]?key|rpc[_ -]?url|worker[_ -]?secret|runtime[_ -]?token|api[_ -]?key|mnemonic|password|seed[_ -]?phrase)["']?\s*[:=]\s*["']?\S+)/i;
function assertNoSensitive(value: string): void {
  if (sensitive.test(value)) throw Error("bounty_report_sensitive_content_detected");
}

type ObjectValue = Record<string, unknown>;
function obj(value: unknown): ObjectValue { return value && typeof value === "object" && !Array.isArray(value) ? value as ObjectValue : {}; }
function array(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
function str(value: unknown): string { return typeof value === "string" ? value : value === null || value === undefined ? "Unavailable" : String(value); }
function cell(value: unknown): string { return str(value); }
function table(columns: string[], rows: unknown[][]): ReportBlock { return { kind: "table", columns, rows: rows.map((row) => row.map(cell)) }; }
function text(value: string): ReportBlock { return { kind: "text", text: value }; }
function list(items: string[]): ReportBlock { return { kind: "list", items }; }
function section(id: string, title: string, ...blocks: Array<ReportBlock | null>): ReportSection {
  return { id, title, blocks: blocks.filter((block): block is ReportBlock => block !== null) };
}
function artifact(pkg: EvidencePackage, type: string): ObjectValue {
  return obj(pkg.artifacts.find((item) => item.type === type)?.data);
}
function rows(value: unknown): ObjectValue[] { return array(value).map(obj); }
function pairs(value: unknown): unknown[][] { return Object.entries(obj(value)).sort(([a], [b]) => a.localeCompare(b)).map(([a, b]) => [a, b]); }
function optionalList(items: string[]): ReportBlock | null { return items.length ? list(items) : null; }
function optionalTable(columns: string[], values: unknown[][]): ReportBlock | null { return values.length ? table(columns, values) : null; }

export function validateBountyReportFields(value: BountyReportFields): BountyReportFields {
  const keys = Object.keys(BOUNTY_REPORT_FIELD_LIMITS) as Array<keyof BountyReportFields>;
  if (!value || Object.keys(value).sort().join() !== [...keys].sort().join()) throw Error("bounty_report_fields_invalid");
  const result = {} as BountyReportFields;
  for (const key of keys) {
    const field = value[key];
    if (typeof field !== "string" || Buffer.byteLength(field, "utf8") > BOUNTY_REPORT_FIELD_LIMITS[key] ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(field)) throw Error(`bounty_report_field_invalid:${key}`);
    result[key] = field.replace(/\r\n?/g, "\n");
    assertNoSensitive(result[key]);
  }
  if (!result.title.trim()) throw Error("bounty_report_title_required");
  return result;
}
export function defaultBountyReportFields(pkg: EvidencePackage): BountyReportFields {
  let title = "";
  for (const char of pkg.subject.title) {
    if (Buffer.byteLength(title + char, "utf8") > BOUNTY_REPORT_FIELD_LIMITS.title) break;
    title += char;
  }
  return { title: title.trim() || "Untitled finding",
    summary: "", impactStatement: "", reproductionNote: "", additionalContext: "" };
}

/** Uses only the verified, finalized G1 JSON. No source, database, network, or execution adapters. */
export function buildBountyReport(pkg: EvidencePackage, fieldsInput: BountyReportFields,
  identity: { reportId: string; revisionOf: string | null; status: "draft" | "finalized";
    createdAt: number; finalizedAt: number | null }): BountyReport {
  if (pkg.status !== "finalized" || verifyEvidencePackageIntegrity(pkg).status !== "valid") throw Error("bounty_report_package_invalid");
  assertNoSensitive(canonicalEvidenceJson(pkg));
  const fields = validateBountyReportFields(fieldsInput);
  const staticContext = artifact(pkg, "static-context"), source = artifact(pkg, "source");
  const graph = artifact(pkg, "protocol-graph-subset"), path = artifact(pkg, "investigation-path");
  const securityViews = rows(pkg.artifacts.find((item) => item.type === "security-views")?.data);
  const poc = artifact(pkg, "reviewed-poc"), fork = artifact(pkg, "fork-identity"), execution = artifact(pkg, "execution");
  const trace = artifact(pkg, "trace"), state = artifact(pkg, "state"), overlay = artifact(pkg, "impact-overlay");
  const flow = artifact(pkg, "asset-flow"), scenario = artifact(pkg, "reviewed-scenario");
  const accounting = artifact(pkg, "scenario-accounting"), replay = artifact(pkg, "replay");
  const scenarioRoles = rows(accounting.roles);
  const roleByAddress = new Map(scenarioRoles.map((role) => [role.address, role.role]));
  const findings = rows(staticContext.findings), traces = rows(trace.traces);
  const boundedTraces = traces.map((t) => {
    const all = rows(t.nodes), picked = new Set(all.slice(0, 16));
    for (const node of all) {
      if (picked.size >= 24) break;
      if (node.outcome === "reverted" || node.outcome === "failed") picked.add(node);
    }
    return { trace: t, nodes: all.filter((node) => picked.has(node)), omitted: all.length - picked.size };
  });
  const transactions = rows(overlay.transactions).length ? rows(overlay.transactions) : traces.map((t) => {
    const receipt = obj(t.receipt), root = rows(t.nodes)[0] ?? {};
    return { ordinal: t.transactionOrdinal, transactionHash: t.transactionHash, sender: root.from,
      to: root.to, valueWei: root.valueWei, status: receipt.status === 1 ? "success" : receipt.status === 0 ? "reverted" : "unavailable",
      localBlockNumber: receipt.blockNumber, localBlockHash: receipt.blockHash, gasUsed: receipt.gasUsed };
  });
  const sections: ReportSection[] = [];
  sections.push(section("summary", "Summary",
    table(["Fact", "Value"], [["Subject type", pkg.subject.type], ["Subject title", pkg.subject.title],
      ["Subject status", pkg.subject.status], ["Dynamic reproduction evidence", pkg.selection.executionId ? "Included" : "Unavailable"],
      ["Bounded replay evidence", pkg.selection.replayRunId ? "Included" : "Unavailable"],
      ["Reported/Existing Severity", pkg.subject.existingSeverity ?? "Unavailable"],
      ["Severity provenance", pkg.subject.existingSeverity ? `Existing ${pkg.subject.type} record in G1 package` : "Unavailable"]]),
    fields.summary ? text(`Researcher-authored summary: ${fields.summary}`) : null,
    fields.impactStatement ? text(`Researcher-authored impact statement: ${fields.impactStatement}`) : null));
  sections.push(section("affected-component", "Affected Component",
    optionalTable(["Finding ID", "Contract", "Function", "Source unit", "Lines", "Status"], findings.map((f) =>
      [f.id, f.contract, f.functionName, f.sourceUnit, `${cell(f.startLine)}–${cell(f.endLine)}`, f.status])),
    source.sourceUnit ? table(["Source unit", "Snapshot SHA-256", "Excerpt lines"],
      [[source.sourceUnit, source.rawSha256, `${source.startLine}–${source.endLine}`]]) : text("Source snapshot excerpt unavailable."),
    typeof source.excerpt === "string" ? { kind: "code", language: "solidity", source: source.excerpt } : null));
  const nodes = rows(graph.nodes), edges = rows(graph.edges);
  sections.push(section("technical-context", "Technical Context",
    optionalTable(["Node", "Kind", "Canonical ID"], nodes.map((n) => [n.name, n.kind, n.id])),
    optionalTable(["From", "Relationship", "To", "Canonical ID"], edges.map((e) => [e.from, e.kind, e.to, e.id])),
    optionalTable(["Path kind", "Static Investigation Path", "Coverage"], rows(path.paths).map((p) =>
      [p.kind, rows(p.steps).map((s) => cell(s.label)).join(" → "), p.completeness])),
    optionalTable(["Security view", "Canonical ID", "Warnings"], securityViews.map((v) =>
      [v.viewType, v.id, array(v.warnings).map(cell).join(", ")])),
    path.paths ? text("This path is derived from static analysis and does not by itself prove runtime exploitability.") :
      text("Static structural context is unavailable in this package.")));
  sections.push(section("finding-context", "Vulnerability / Finding Context",
    table(["Subject ID", "Type", "Status", "Existing confidence"],
      [[pkg.subject.id, pkg.subject.type, pkg.subject.status, pkg.subject.existingConfidence]]),
    optionalTable(["Finding ID", "Status", "Scanner/source", "Detector", "Existing severity", "Existing confidence"],
      findings.map((f) => [f.id, f.status, f.scanner, f.detectorId, f.existingSeverity, f.existingConfidence]))));
  if (pkg.selection.executionId) {
    sections.push(section("reproduction", "Reproduction",
      text("Reproduction was performed only against ContractHunter's isolated local fork. No transaction was sent to the upstream/live network."),
      table(["Fact", "Value"], [["Reviewed PoC ID", poc.id], ["PoC source SHA-256", poc.sourceSha256],
        ["Entry contract", poc.entryContract], ["Compiler identity", "Unavailable in G1 package"],
        ["Forge version", poc.forgeVersion], ["Forge SHA-256", poc.forgeSha256],
        ["Chain ID", fork.chainId], ["Fork block", fork.forkBlock], ["Fork block hash", fork.forkBlockHash],
        ["Anvil version", fork.anvilVersion], ["Anvil SHA-256", fork.anvilSha256]]),
      optionalTable(["Target address", "Deployed code hash"], pairs(fork.targetCodeHashes)),
      fields.reproductionNote ? text(`Researcher-authored reproduction note: ${fields.reproductionNote}`) : null,
      text("The reviewed PoC source and local environment identity are included. Automated reproduction command reconstruction is unavailable from G1 evidence."),
      typeof poc.source === "string" ? { kind: "code", language: "solidity", source: poc.source } :
        text("Reviewed PoC source unavailable in this package.")));
    sections.push(section("observed-execution", "Observed Execution",
      table(["Fact", "Value"], [["Execution ID", execution.id], ["Status", execution.status],
        ["Executed", execution.executed], ["Transaction scope", execution.transactionScope],
        ["Trace capture", execution.traceCaptureStatus], ["Final reset", execution.finalReset]]),
      optionalTable(["Index", "Hash", "From", "To", "Value (wei)", "Status", "Local block", "Gas used"],
        transactions.map((tx) => [tx.ordinal, tx.transactionHash, tx.sender, tx.to, tx.valueWei, tx.status,
          `${cell(tx.localBlockNumber)} / ${cell(tx.localBlockHash)}`, tx.gasUsed])),
      !transactions.length ? text("Transaction details unavailable in the package; execution hashes: " +
        array(execution.transactionHashes).map(cell).join(", ")) : null));
    sections.push(section("trace", "Transaction Trace",
      ...boundedTraces.map(({ nodes }) => ({ kind: "code" as const, language: "text", source: nodes.map((n) =>
        `${"  ".repeat(Math.max(0, Math.min(Number(n.depth) || 0, 24)))}${cell(n.callType)} ${cell(n.to)} ${cell(n.selector)} ` +
        `[${cell(n.outcome)}; input ${cell(n.inputByteLength)} bytes; SHA-256 ${cell(n.inputSha256)}]`).join("\n") })),
      ...boundedTraces.map(({ trace: t, nodes, omitted }) => text(`${cell(t.transactionHash)}: ${nodes.length} bounded call rows shown; ${omitted} omitted. Full normalized trace remains in the G1 package.`)),
      ...boundedTraces.map(({ trace: t, nodes }) => table(["Tx", "Call ID", "Depth", "Call", "From", "To", "Value (wei)", "Selector", "Input bytes", "Input SHA-256", "Outcome"],
        nodes.map((n) => [t.transactionHash, `${cell(t.id)}:${cell(n.ordinal)}`, n.depth, n.callType, n.from, n.to, n.valueWei,
          n.selector, n.inputByteLength, n.inputSha256, n.outcome]))),
      !traces.length ? text("Normalized trace unavailable.") : null,
      text("Calldata previews are unavailable in the G1 trace projection; selectors, byte lengths and hashes are retained.")));
    sections.push(section("static-vs-observed", "Static vs Observed",
      optionalTable(["Observed relationship", "Count"], Object.entries(rows(overlay.calls).reduce<Record<string, number>>((out, c) => {
        const key = cell(c.relationshipStatus); out[key] = (out[key] ?? 0) + 1; return out;
      }, {})).sort(([a], [b]) => a.localeCompare(b)).map(([key, count]) => [key, count])),
      optionalTable(["Static path", "Edge", "Comparison"], rows(overlay.pathComparisons).flatMap((p) =>
        rows(p.edges).map((e) => [p.pathId, e.edgeId, e.status]))),
      !rows(overlay.calls).length && !rows(overlay.pathComparisons).length ?
        text("Static-versus-observed comparison unavailable in this package.") : null,
      text("Not observed in this local execution does not mean impossible in other executions.")));
    const diff = obj(state.diff);
    sections.push(section("state-changes", "State Changes",
      optionalTable(["Observation", "Kind", "PRE", "POST", "Delta", "Status"], rows(diff.changes).map((c) =>
        [c.id, c.kind, c.before, c.after, c.delta, `${cell(c.beforeStatus)} → ${cell(c.afterStatus)}`])),
      !diff.changes ? text("State diff unavailable or partial.") : null,
      text("State changes were observed during the execution. Unless explicitly proven by the evidence model, they are not attributed to a specific trace call.")));
    sections.push(section("asset-movement", "Asset Movement / Impact Evidence",
      optionalTable(["Tx", "Asset", "From", "To", "Amount (raw)", "Movement type", "Evidence"],
        rows(flow.ledgerEntries).map((e) => [e.transactionOrdinal, e.assetId, e.from, e.to, e.amount, e.movementKind, e.evidenceId])),
      optionalTable(["Attempted tx", "Asset", "From", "To", "Amount (raw)", "Reason"],
        rows(flow.attemptedFlows).map((e) => [e.transactionOrdinal, e.assetId, e.from, e.to, e.amount, e.reason])),
      optionalTable(["Participant", "Asset", "Incoming", "Outgoing", "Net Observed Movement"],
        rows(flow.netPositions).map((p) => [p.participant, p.assetId, p.incoming, p.outgoing, p.netObservedMovement])),
      optionalTable(["Tx", "Gas used", "Effective gas price", "Execution cost (wei)"],
        rows(flow.transactions).map((t) => { const c = obj(t.executionCost); return [t.ordinal, c.gasUsed, c.effectiveGasPrice, c.amountWei]; })),
      text("Local execution cost is separate from protocol asset movement."),
      text("Reconciliation compares directional movement evidence with captured PRE/POST balances."),
      optionalTable(["Observation", "Status", "PRE", "POST", "Ledger net", "Difference"],
        rows(flow.reconciliation).map((r) => [r.observationId, r.status, r.before, r.after, r.ledgerNet, r.difference]))));
  }
  if (pkg.selection.scenarioRevisionId) {
    sections.push(section("scenario-analysis", "Reviewed Scenario Analysis",
      text("Scenario roles are explicit researcher annotations used for accounting. They do not independently establish attacker identity, ownership, victim status or exploitability."),
      table(["Scenario ID", "Revision", "Reviewed revision ID", "Status"],
        [[scenario.scenarioId, scenario.revision, scenario.id, scenario.status]]),
      optionalTable(["Role", "Participant"], scenarioRoles.map((r) => [r.role, r.address])),
      optionalTable(["Participant", "Reviewed scenario role", "Observed context label"], rows(flow.participants).map((p) =>
        [p.address, roleByAddress.get(p.address) ?? "unassigned", p.label])),
      optionalTable(["Asset", "Role", "Incoming", "Outgoing", "Net observed"],
        rows(accounting.rolePositions).filter((p) => p.transactionOrdinal === null).map((p) =>
          [p.assetId, p.role, p.incoming, p.outgoing, p.netObservedMovement])),
      optionalTable(["Asset", "Direction", "Direct amount", "Ledger IDs"],
        rows(accounting.directRoleTransfers).filter((p) => p.transactionOrdinal === null).map((p) =>
          [p.assetId, p.direction, p.amount, array(p.ledgerEntryIds).map(cell).join(", ")]))));
  }
  if (pkg.selection.replayRunId) {
    const plan = obj(replay.plan), run = obj(replay.run), result = obj(replay.result);
    sections.push(section("repeatability", "Repeatability Evidence",
      table(["Fact", "Value"], [["Mode", result.mode], ["Requested iterations", result.requestedIterations],
        ["Completed iterations", result.completedIterations], ["Matching iterations", result.matchingIterations],
        ["Repeatability classification", result.repeatability], ["Stop reason", result.stopReason],
        ["Final reset", run.finalReset], ["Reviewed plan", plan.id]]),
      optionalTable(["Iteration", "Status", "Matched reference", "Variation", "Stop reason"],
        rows(result.iterations).map((entry) => { const i = obj(entry.iteration); return [i.index, i.status,
          entry.matchedReference, array(entry.variation).map(cell).join(", "), i.stopReason]; })),
      result.mode === "independent-replay" && result.repeatability === "reproduced-consistently" ?
        text(`${cell(result.matchingIterations)} of ${cell(result.completedIterations)} bounded independent repetitions produced equivalent reviewed scenario accounting from the same baseline.`) : null,
      result.mode === "independent-replay" ? text("Independent repetitions start from the same baseline. Their movements are not summed as cumulative impact.") : null,
      result.mode === "cumulative-replay" ? text(`The following cumulative movement was observed after ${cell(result.completedIterations)} completed local repetitions only. No later repetitions are projected.`) : null,
      result.mode === "cumulative-replay" ? optionalTable(["Asset", "Role", "Completed-iteration incoming", "Outgoing", "Net observed"],
        rows(result.cumulativePositions).map((p) => [p.assetId, p.role, p.incoming, p.outgoing, p.netObservedMovement])) : null,
      result.mode === "cumulative-replay" ? optionalTable(["Asset", "Direction", "Completed-iteration direct amount"],
        rows(result.cumulativeDirect).map((p) => [p.assetId, p.direction, p.amount])) : null,
      text("Bounded replay does not establish unlimited repeatability, maximum protocol impact or real-chain exploitability.")));
  }
  sections.push(section("assumptions", "Assumptions", optionalList(pkg.assumptions)));
  sections.push(section("limitations", "Limitations", optionalList(pkg.limitations),
    optionalList([...(flow.status === "partial" ? ["Asset accounting is partial within the captured evidence."] : []),
      ...(Number(obj(overlay.coverage).unmappedCallCount) > 0 ? ["Some runtime calls have no canonical source mapping."] : []),
      ...(pkg.selection.scenarioRevisionId ? ["Scenario roles are manual researcher annotations."] : [])]),
    optionalList(pkg.warnings.map((w) => `${w.artifactId}: ${w.message}`))));
  sections.push(section("evidence-provenance", "Evidence & Provenance",
    table(["Evidence Package", "Content hash", "Artifact count"],
      [[pkg.packageId, pkg.contentHash, pkg.manifest.length]]),
    text("The full machine-readable evidence is the finalized G1 JSON package. The report is a presentation of that package and researcher-authored text.")));
  sections.push(section("appendix", "Appendix",
    fields.additionalContext ? text(`Researcher-authored additional context: ${fields.additionalContext}`) :
      text("No researcher-authored additional context."),
    table(["Type", "ID", "Version", "Hash", "Status"], pkg.manifest.map((m) =>
      [m.type, m.id, m.schemaVersion, m.contentHash, m.status])),
    optionalTable(["Input", "Derived / linked"], pkg.provenance.map((p) => [p.from, p.to])),
    table(["Integrity fact", "Value"], [["Evidence Package ID", pkg.packageId], ["Package schema", pkg.schema],
      ["Package ruleset", pkg.rulesetVersion], ["Manifest hash", pkg.manifestHash],
      ["Package content hash", pkg.contentHash], ["Package integrity", "valid"],
      ["Report schema", BOUNTY_REPORT_SCHEMA], ["Report ruleset", BOUNTY_REPORT_RULESET]]),
    pkg.selection.executionId ? table(["Local environment", "Value"],
      [["Chain ID", fork.chainId], ["Fork block", fork.forkBlock], ["Fork block hash", fork.forkBlockHash]]) : null,
    optionalList(pkg.warnings.map((w) => `${w.artifactId}: ${w.message}`)),
    optionalList(pkg.limitations)));
  const semantic = { rulesetVersion: BOUNTY_REPORT_RULESET, evidencePackageId: pkg.packageId,
    evidencePackageContentHash: pkg.contentHash, evidenceManifestHash: pkg.manifestHash,
    packageCompleteness: pkg.completeness, capabilities: pkg.capabilities, fields, sections };
  return { schema: BOUNTY_REPORT_SCHEMA, ...semantic, ...identity,
    contentHash: evidenceHash(BOUNTY_REPORT_SCHEMA, semantic) };
}

export function verifyBountyReport(report: BountyReport, pkg: EvidencePackage): boolean {
  try {
    const rebuilt = buildBountyReport(pkg, report.fields, { reportId: report.reportId,
      revisionOf: report.revisionOf, status: report.status, createdAt: report.createdAt, finalizedAt: report.finalizedAt });
    return canonicalEvidenceJson(rebuilt) === canonicalEvidenceJson(report);
  } catch { return false; }
}

export function verifyBountyReportIntegrity(report: BountyReport, pkg: EvidencePackage | null):
  { status: "valid" | "invalid" | "unavailable"; reasons: string[] } {
  if (!pkg) return { status: "unavailable", reasons: ["bound_evidence_package_unavailable"] };
  if (verifyEvidencePackageIntegrity(pkg).status !== "valid")
    return { status: "invalid", reasons: ["bound_evidence_package_integrity_invalid"] };
  return verifyBountyReport(report, pkg) ? { status: "valid", reasons: [] } :
    { status: "invalid", reasons: ["report_content_or_binding_invalid"] };
}

function escapePlain(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/\\/g, "\\\\").replace(/([`*_{}\[\]()#+!|~])/g, "\\$1")
    .replace(/\n/g, " ⏎ ");
}
function fence(source: string): string {
  let longest = 0;
  for (const match of source.matchAll(/`+/g)) longest = Math.max(longest, match[0].length);
  return "`".repeat(Math.max(3, longest + 1));
}
export function renderBountyReportMarkdown(report: BountyReport): string {
  const lines = [`# ${escapePlain(report.fields.title)}`, "", "DRAFT BUG-BOUNTY REPORT".replace("DRAFT", report.status === "finalized" ? "FINALIZED" : "DRAFT"),
    "", `Report ID: ${escapePlain(report.reportId)}`, `Report content hash: ${escapePlain(report.contentHash)}`,
    `Evidence Package ID: ${escapePlain(report.evidencePackageId)}`,
    `Revision of: ${escapePlain(report.revisionOf ?? "Initial revision")}`,
    `Created: ${new Date(report.createdAt).toISOString()}`,
    `Finalized: ${report.finalizedAt === null ? "Unavailable" : new Date(report.finalizedAt).toISOString()}`,
    `Evidence capability: ${escapePlain(report.packageCompleteness)}`, ""];
  for (const section of report.sections) {
    lines.push(`## ${escapePlain(section.title)}`, "");
    for (const block of section.blocks) {
      if (block.kind === "text") lines.push(escapePlain(block.text), "");
      if (block.kind === "list") { for (const item of block.items) lines.push(`- ${escapePlain(item)}`); lines.push(""); }
      if (block.kind === "table") {
        lines.push(`| ${block.columns.map(escapePlain).join(" | ")} |`,
          `| ${block.columns.map(() => "---").join(" | ")} |`);
        for (const row of block.rows) lines.push(`| ${row.map(escapePlain).join(" | ")} |`);
        lines.push("");
      }
      if (block.kind === "code") { const marker = fence(block.source); lines.push(`${marker}${block.language}`, block.source, marker, ""); }
    }
  }
  return `${lines.join("\n").replace(/\r\n?/g, "\n").trimEnd()}\n`;
}
