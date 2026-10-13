import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { StaticProtocolGraphArtifact } from "@contracthunter/core";
import { ProtocolMap } from "./protocol-map";

const artifact = { schema: "contracthunter-static-protocol-graph-v1", contentSha256: "c".repeat(64),
  graph: { schema: "contracthunter-protocol-graph-v1", id: "pg:" + "b".repeat(64),
    scanId: "11111111-1111-4111-8111-111111111111", nodes: [], edges: [], warnings: [] },
  findingLinks: [], unresolved: [] } as unknown as StaticProtocolGraphArtifact;

describe("Protocol Map Security View controls", () => {
  it("renders all closed views, Overview, static warning and accessible controls", () => {
    const html = renderToStaticMarkup(<ProtocolMap artifact={artifact} scanId={artifact.graph.scanId} initialView="money-flow" />);
    for (const label of ["Overview", "Money Flow", "Permissions", "Oracle Flow", "External Calls",
      "Upgradeability", "Attack Surface", "Findings"]) expect(html).toContain(label);
    expect(html).toContain('aria-label="Security views"');
    expect(html).toContain("Loading money flow view");
    expect(html).toContain("Research details");
    expect(html).not.toContain("dangerouslySetInnerHTML");
  });
  it("escapes hostile repository labels in textual selected details", () => {
    const poisoned = structuredClone(artifact);
    poisoned.graph.nodes.push({ id: "pn:" + "d".repeat(64), key: "fixture", kind: "contract",
      name: "Vault<script>alert(1)</script>", qualifiedName: "src/Vault.sol:Vault", contractKind: "contract",
      abstract: false, repositoryClassification: { effective: "core", automatic: "core", automaticOrigin: "path-pattern",
        reasons: [], override: null }, source: null, evidence: [], characteristics: [] } as never);
    const html = renderToStaticMarkup(<ProtocolMap artifact={poisoned} scanId={artifact.graph.scanId}
      initialSelectedId={poisoned.graph.nodes[0].id} />);
    expect(html).toContain("Vault&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert(1)</script>");
  });
});
