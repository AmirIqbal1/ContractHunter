import type { ImpactOverlay, StaticProtocolGraphArtifact } from "@contracthunter/core";
import type { MapView } from "./protocol-map";

/** Ephemeral renderer objects. Neither these IDs nor edges enter ProtocolGraph. */
export function runtimeMapOverlay(artifact: StaticProtocolGraphArtifact, view: MapView, overlay: ImpactOverlay,
  transactionOrdinal = 0) {
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  const shown = new Set(view.nodes.map((node) => node.id));
  const limit = Math.min(80, Math.floor(Math.max(0, 600 - view.nodes.length) / 2));
  const transactionCalls = overlay.observedCalls.filter((call) => call.transactionOrdinal === transactionOrdinal);
  const calls = transactionCalls.slice(0, limit);
  const maxX = Math.max(0, ...view.nodes.map((node) => node.position.x + 210));
  const nodes: MapView["nodes"] = [], edges: MapView["edges"] = [];
  for (const [index, call] of calls.entries()) {
    const owner = (id: string | null) => {
      const node = id ? byId.get(id) : null;
      return node?.kind === "function" ? node.contractId : node?.id ?? null;
    };
    const parent = call.parentCallId ? transactionCalls.find((item) => item.id === call.parentCallId) : null;
    const sourceOwner = owner(parent?.mapping.functionNodeId ?? parent?.mapping.contractNodeId ?? null);
    const targetOwner = owner(call.mapping.functionNodeId ?? call.mapping.contractNodeId);
    const source = sourceOwner && shown.has(sourceOwner) ? sourceOwner : `io:${overlay.executionId}:${call.id}:from`;
    const target = targetOwner && shown.has(targetOwner) ? targetOwner : `io:${overlay.executionId}:${call.id}:to`;
    for (const [id, address, column, mapped] of [[source, call.from, 0, !!sourceOwner], [target, call.to, 1, !!targetOwner]] as const) {
      if (shown.has(id)) continue;
      nodes.push({ id, type: "protocol", position: { x: maxX + 90 + column * 280, y: index * 125 },
        data: { label: address ? `${address.slice(0, 8)}…${address.slice(-6)}` : "runtime target unavailable",
          kind: "runtime-target", classification: "observed", badges: [mapped ? "MAPPED · HIDDEN BY STATIC FILTER" : "STATIC IDENTITY UNRESOLVED"],
          findingCount: 0, source: null, selected: false, dimmed: false } });
    }
    edges.push({ id: `io:${overlay.executionId}:${call.id}:edge`, source, target,
      label: call.relationshipStatus === "runtime-only-observed" ? "RUNTIME-ONLY OBSERVED CALL" : `OBSERVED ${call.callType}`,
      type: "smoothstep", animated: false, style: { stroke: "#65d8aa", strokeWidth: 2, strokeDasharray: "7 5" },
      data: { kind: call.callType, sourceLocation: null, dimmed: false } });
  }
  return { nodes, edges, clippedCalls: transactionCalls.length - calls.length };
}
