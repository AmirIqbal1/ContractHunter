import type { ProtocolGraphNode, SecurityViewResult, SecurityViewType, StaticProtocolGraphArtifact } from "@contracthunter/core";
import { mapOwner } from "./protocol-map";

export const securityMapViews: Array<{ value: SecurityViewType; label: string }> = [
  { value: "money-flow", label: "Money Flow" }, { value: "permissions", label: "Permissions" },
  { value: "oracle-flow", label: "Oracle Flow" }, { value: "external-calls", label: "External Calls" },
  { value: "upgradeability", label: "Upgradeability" }, { value: "attack-surface", label: "Attack Surface" },
  { value: "findings", label: "Findings" },
];
export type SecurityMapView = SecurityViewType | "overview";
export const parseSecurityMapView = (value: string | null | undefined): SecurityMapView =>
  securityMapViews.some((item) => item.value === value) ? value as SecurityViewType : "overview";

export const reasonHelp: Record<string, string> = {
  "contains-included-function": "This contract contains a function included by a static fact in this view.",
  "relationship-endpoint": "This graph identity is an endpoint of an included source-backed relationship.",
  "token-transfer": "This function performs a token-transfer-like operation. Asset identity and direction may be unresolved.",
  "native-value-transfer": "A call carries native value. This static fact does not establish an observed transfer.",
  "transfer-relationship": "The graph contains explicit transfer-like relationship evidence; inspect the source before inferring direction.",
  "external-call": "Control may leave this contract and enter another contract.",
  "target-not-statically-resolved": "The destination could not be proven from static evidence.",
  "low-level-call": "A low-level call appears in source; inspect its target and return handling.",
  "delegatecall-present": "Runs another contract's code using this contract's storage and context.",
  "owner-controlled": "An ownership control relationship was detected in code. This does not prove secure authorization.",
  "role-controlled": "A role control relationship was detected in code. Its exact authority follows the cited source.",
  "privileged-operation": "A control relationship protects this specific operation; it does not establish overall contract security.",
  "proxy": "Static evidence identifies this contract as a proxy.",
  "proxy-implementation": "This relationship connects a proven proxy and implementation.",
  "upgradeable": "Static evidence identifies an upgrade relationship; inspect the cited control and implementation facts.",
  "upgrade-authority": "This role or relationship can modify a proven upgradeable component.",
  "oracle-like-dependency": "Static evidence classifies this dependency as oracle-like.",
  "payable": "This externally callable function can receive native currency.",
  "externally-callable": "This function can be called from outside the contract; permissions may still apply.",
  "state-changing": "Static state-write evidence is associated with this externally callable function.",
  "assembly-present": "Inline assembly or Yul is present; static interpretation may be less complete.",
  "callback-hook": "Exact signature or interface evidence identifies a callback or hook.",
  "finding-linked": "A ContractHunter finding is attached to this exact graph identity.",
  "call-site-with-transfer-like-operation": "This call site carries a transfer-like operation fact, without proving an asset path.",
};
export function projectionOwnerIds(artifact: StaticProtocolGraphArtifact, projection: SecurityViewResult): Set<string> {
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  return new Set(projection.nodes.flatMap(({ id }) => {
    const node = byId.get(id);
    return node ? [mapOwner(node, byId).id] : [];
  }));
}
export function projectionNodeFacts(artifact: StaticProtocolGraphArtifact, projection: SecurityViewResult,
  ownerId: string) {
  const byId = new Map(artifact.graph.nodes.map((node) => [node.id, node]));
  return projection.nodes.flatMap((item) => {
    const node = byId.get(item.id);
    return node && mapOwner(node, byId).id === ownerId ? [{ node, reasons: item.reasons }] : [];
  });
}
export function projectionHasNode(artifact: StaticProtocolGraphArtifact, projection: SecurityViewResult,
  nodeId: string): boolean {
  const byId = new Map<string, ProtocolGraphNode>(artifact.graph.nodes.map((node) => [node.id, node]));
  const node = byId.get(nodeId);
  return !!node && projectionOwnerIds(artifact, projection).has(mapOwner(node, byId).id);
}
