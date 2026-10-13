# Finding integration audit — Protocol Intelligence Phase 9A

## Baseline and exact authority

Released package version remains `0.2.2`; development has 15 migrations. The static graph is `contracthunter-protocol-graph-v1`, and its persisted artifact is `contracthunter-static-protocol-graph-v1`. `findingLinks` contain exact `(findingId, nodeId)` pairs. The general overlay schema permits finding node or edge refs, but the current persisted static artifact links findings to nodes only. The static generator requires an aligned canonical source unit and contract identity. It chooses a function only when its name and source line uniquely identify a function within that exact contract; otherwise it retains the contract attachment. There is no basename-only fallback in the path model.

Findings are scanner records with ID, scan, detector/source, fingerprint, source span, severity, confidence and status (`candidate`, `investigating`, `verified`, `rejected`). Existing Investigations group correlated findings through `investigation_findings`; they have their own priority, confidence, category and status with the same four-state vocabulary. Hypotheses have `candidate`, `investigating`, `likely-valid`, `verified`, `rejected`, and may hold exact related Investigation IDs. Their free-text affected contract/function fields are **not** canonical graph links and are excluded from path resolution. Verification and Impact Lab remain separate authorities.

| Layer | Audit result | Scope |
| --- | --- | --- |
| ProtocolGraph node attachment | Implemented | Exact persisted finding-to-node link; graph overlay schema also supports edge refs, but static artifact does not persist them. |
| Function attachment | Partial | Exact source unit/contract and unique function line; ambiguous functions attach to contract. |
| Edge and operation attachment | Intentionally deferred | No exact persisted finding-to-edge/operation mapping; Function Explorer correctly shows function-level findings only. |
| Protocol Map badges/navigation | Implemented | Exact node/contract badges and finding routes. |
| Findings Security View | Implemented | Exact linked nodes, bounded references and unmapped summary. |
| Contract Explorer | Implemented | Contract/function finding references, status and source navigation. |
| Function Explorer | Partial | Exact function refs, no fabricated operation badge. |
| Start Here | Implemented | Exact finding factors/counts and Explorer links; no status elevation. |
| Finding detail | Phase 9A expanded | Exact graph attachment now offers Map, Explorer and canonical source links. |
| Investigation and hypothesis routes | Partial | Existing finding membership and hypothesis Investigation IDs; no visual static path yet. |
| Verification / Impact Lab | Intentionally separate | Existing review and execution authority; a path does not launch or change it. |

## Investigation Path v1

`contracthunter-investigation-path-v1` is a deterministic, frontend-independent **static research context** model. `contracthunter-investigation-path-deriver-v1` uses the validated immutable graph and exact `findingLinks`. Finding, existing Investigation, and Hypothesis are closed subject types. Investigation and Hypothesis subjects resolve through their persisted finding membership; if no exact link exists, the result is `unmapped`, without interpreting free-text affected names. One finding may retain multiple exact target IDs. A contract-level target remains contract-level.

Closed path kinds are `local-context`, `caller-chain`, `callee-chain`, `privilege-context`, `oracle-context`, `upgrade-context`, and `asset-operation-context`. Caller/callee chains traverse only exact static call edges. Entry point chains mean **statically connected from an external entry point**, never permissionless or exploitable. Oracle and Money Flow context require the existing deterministic Security View projection; upgrade context requires a proven `upgrades` edge, not delegatecall alone. Function operation references reuse Phase 6 IDs and source positions. Each path step carries canonical node/edge IDs, source, edge reasons, provenance, finding IDs, uncertainty and a fixed Beginner concept key. Unresolved targets terminate a path; no endpoint is invented.

Bounds: 32 finding refs/targets, 24 paths, depth 3, 2,048 explored edges, 5 steps/path, 48 operation refs, 16 warnings and 8 evidence records/step. Paths are ordered by closed kind, then length and canonical identity. Cycles cannot repeat a node within a path. Coverage is `complete-within-bounds`, `partial`, `truncated`, or `unresolved`; it is never an absolute completeness claim. Subject membership truncation and unmapped finding refs are explicit. Results have versioned deterministic content hashes and are derived on read, with no migration or cache. The read-only endpoint is `GET /api/scans/:id/protocol-graph/investigation-paths/:subjectType/:subjectId`; IDs and same-scan ownership are validated. No arbitrary path query or browser weights exist.

A structural path only reports static relationships among cited graph identities. It is not proof of runtime reachability, exploitability, a verified attack path, a PoC or a lifecycle decision. D1 observed calls and C1 observed state changes may later attach through separate exact execution references; they must never rewrite static path facts. Phase 9B will render the model. No Phase 9B visual path UI exists yet.
