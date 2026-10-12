# API reference

## Static Security Views (Phase 7A)

`GET /api/scans/:id/protocol-graph/security-views/:view` accepts exactly `money-flow`, `permissions`, `oracle-flow`, `external-calls`, `upgradeability`, `attack-surface` or `findings`. It returns a bounded `contracthunter-security-view-v1` projection with existing graph IDs, inclusion reasons/provenance, static annotations, counts, warnings and a deterministic content hash. Finding metadata is loaded only by exact same-scan finding ID and capped at 500 entries. Invalid scan/view selectors return 400, missing scan/graph returns 404 and integrity/derivation failures return a sanitized 500. The endpoint is read-only and does not provide a query language, runtime trace or mutation route.

## Visual Function Explorer (Phase 6B)

The page route is `/hunts/:scanId/contracts/:contractId/functions/:functionId`, linked from Contract Explorer. It reuses the read-only Phase 6A API/service and adds no browser-controlled analysis or mutation endpoint. The function response includes bounded exact related node labels, proven control-role labels and a proven-proxy flag to support navigation; it still returns only one function model, not the full graph. Wrong scan/contract/function ownership is rejected. Presentation query keys `operation`, `mode` and `filter` are bounded selectors and carry no source content.

## Function Explorer Phase 6A

`GET /api/scans/:scanId/protocol-graph/contracts/:contractId/functions/:functionId` returns the exact function model plus a bounded source preview and Phase 6B related-node/control labels for the selected scan and contract. IDs are validated; malformed selectors return 400, missing scan or function returns 404, and graph integrity failure returns a sanitized 500. The versioned model contains source-order operations, callers/callees, state references, finding IDs, review cues, summary, provenance, analysis status and warnings. The optional strict UTF-8 preview comes only from a checksum-matched immutable scan snapshot and is limited to 4 KiB. This endpoint is read-only; it does not expose a CFG or raw scanner JSON.

## Protocol Intelligence Phase 5 Contract Explorer

`/hunts/:scanId/contracts/:contractId` is a server-rendered, read-only contract page. It accepts only a canonical ProtocolGraph contract/interface/library node ID from the validated graph for that scan. Wrong, malformed or cross-scan identities return 404. The server derives a bounded contract neighborhood and joins only exact finding references from the same scan. There is no contract mutation, arbitrary source path, Impact Lab execution, or browser-supplied graph relationship API.

## Impact Lab Phase D1 local traces

`GET /api/impact/poc-executions/:id` adds nullable `traceCaptureStatus`, `traceCount`, `traceNodeCount`, `traceErrorCode`, `traceAvailable` and ordered `traceIds`. `GET /api/impact/poc-executions/:id/traces` reads finalized bounded local receipt/log/call-tree artifacts and returns a failed or empty capture status where applicable. It accepts no transaction hash, RPC method, endpoint or command input. Historical executions return null trace status and an empty list. Trace facts confer no vulnerability authority.

## Impact Lab Phase C1 state capture

`POST /api/impact/sessions/:sessionId/poc-executions` accepts `pocArtifactId` and optional `observations` with typed `nativeBalances`, `erc20Balances` (`token`, `holder`), `erc721Owners` (`token`, decimal `tokenId`), `erc1155Balances` (`token`, `holder`, decimal `tokenId`), `storageSlots` (`contract`, exact 32-byte `slot`), and `viewCalls` (fixed `erc20_totalSupply`, `target`). Unknown keys, arbitrary methods/calldata and oversized plans are rejected. Defaults include sender and target native balances. `GET /api/impact/poc-executions/:id` includes nullable `preSnapshotId`, `postSnapshotId`, `diffId`, `stateCaptureAvailable` and `stateChangeCount`. `GET /api/impact/poc-executions/:id/state` returns the finalized PRE/POST and diff artifacts or null links for historical B1 runs. State endpoints are read-only and do not admit vulnerability evidence.

## Impact Lab Phase B1 manual PoCs

- `POST /api/impact/pocs` — create a **draft** manual artifact with exactly one `findingId` or `hypothesisId`, literal `filename: "ImpactPoC.s.sol"`, bounded `source`, `entryContract`, and optional `revisionOf`. No execution occurs.
- `GET /api/impact/pocs/:id` — inspect artifact and review state.
- `POST /api/impact/pocs/:id/review` — body `{ "decision": "reviewed" | "rejected" }` for a draft. Reviewed source is immutable.
- `POST /api/impact/sessions/:sessionId/poc-executions` — explicit reviewed artifact selector and optional C1 typed observation plan. The service reloads a ready managed fork, checks its current runtime token, reviewed source identity and target, then executes on the local fork only.
- `GET /api/impact/poc-executions/:id` — bounded local reproduction status, diagnostics and provenance. Transaction hashes are local Impact Lab transactions.

All request objects are strict. Raw RPC URL, image, command, argv, Foundry flags, wallet and environment fields are rejected. B1 has no generic RPC or automatic evidence/lifecycle promotion endpoint.

Impact Lab Phase A2 has configured-reference session routes described below. Phase A3 adds an internal session-ID-only probe-runtime service and no public runtime route. There is no generic raw RPC API. B1 adds the narrow reviewed manual PoC routes above.

## Scans

- `POST /api/scans` — validate and enqueue a scan
- `GET /api/scans` — list scans
- `GET /api/scans/:id` — retrieve scan details and related records
- `GET /api/scans/:id/repository-map` — read the finalized bounded Repository Map for this scan; 404 when no map was generated. This is navigation metadata, not a vulnerability score or source-authority upgrade.
- `GET /api/scans/:id/protocol-graph` — read the finalized, integrity-checked static ProtocolGraph artifact; 404 when unavailable. It includes source-linked structure, bounded function facts, exact finding references, unresolved relationships and factual summary counts. It contains no runtime overlay or vulnerability verdict.
- `POST /api/scans/:id/ai-analysis` — manually run/rerun protocol analysis
- `GET /api/scans/:id/ai-context` — preview bounded AI context/cost metadata

## Findings and investigations

- `GET /api/findings` and `GET /api/findings/:id` — list/retrieve findings
- `GET /api/investigations` and `GET /api/investigations/:id` — list/retrieve correlated investigations
- `PATCH /api/investigations/:id` — update investigation status

## Protocol and review

- `GET /api/protocol-analyses/:id` — retrieve an analysis and invariants
- `GET /api/invariants` and `GET /api/invariants/:id` — list/retrieve invariants
- `PATCH /api/invariants/:id` — accept/reject an invariant
- `GET /api/scans/:id/security-review` — preview specialist review/cost
- `POST /api/scans/:id/security-review` — manually run/rerun specialist review

## Hypotheses and verification

- `GET /api/hypotheses` and `GET /api/hypotheses/:id` — list/retrieve hypotheses
- `PATCH /api/hypotheses/:id` — update an allowed non-authoritative hypothesis status; `verified` is never accepted and invalid transitions return a conflict
- `GET /api/hypotheses/:id/verification-options` — read-only deterministic options for structured verification, Foundry fuzz/stateful invariants, and Echidna stateful invariants, in display order. Each option has separate `strategy`, `engine`, `planMode`, `compatibility`, bounded `reasons`, and `selectionAvailable`. Unknown remains distinct from incompatible; this endpoint never generates a plan, invokes AI, executes a worker, or changes status/evidence. A 404 means the hypothesis does not exist.
- `GET /api/hypotheses/:id/verification-target` — read-only, freshly computed advisory target and planning candidates. Returns `{target}` with `targetId`, bounded root-cause family/label, representative ID and reason, current representative flag, related hypothesis IDs/count, strategy readiness, `candidateCount`, and up to 100 ordered candidates (`artifactId`, type, origin hypothesis ID, selected strategy or legacy marker, exact property-target IDs, `eligible|stale|incompatible`, bounded reasons, validation state, execution-history flag, creation time). No query parameters are accepted. An eligible candidate is not automatically reused or executed; a recorded validation response without a persisted run is not treated as validation history.
- `POST /api/hypotheses/:id/verification-options/:strategy/generate` — bodyless explicit strategy-aware plan generation. `strategy` is one of `structured-verification`, `foundry-fuzz-property`, `foundry-stateful-invariant`, or `echidna-stateful-invariant`; the server recomputes compatibility from persisted evidence before one optional AI request. Incompatible/unknown selections return `409` with bounded codes and no provider call. Accepted structured requests return `{selectedStrategy, result, attempt}` and persist a planning attempt; invariant requests return `{selectedStrategy, proposal}` with persisted strategy provenance. Generated plans are reviewable and unexecuted. Actual body bytes above 1,024 return `413`; any nonempty body within that limit returns `400`.
- `POST /api/hypotheses/:id/verification-plan` — generate a non-executing plan preview
- `POST /api/hypotheses/:id/verify` — validate and explicitly execute a local plan
- `GET /api/hypotheses/:id/verifications` — list verification history
- `GET /api/hypotheses/:id/invariant-proposals` — list bounded proposal and invariant-run history
- `POST /api/hypotheses/:id/invariant-proposals` — manually request one AI semantic proposal; bodyless, no execution
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/validate` — bodyless revalidation of a persisted plan and source; returns bounded Foundry and Echidna compatibility with reason codes
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/run/foundry` — bodyless explicit Foundry execution
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/run/echidna` — bodyless explicit Echidna execution; incompatible plans return a conflict before workspace or worker use
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/run` — historical Foundry alias
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/runs/:runId/replays` — generate a deterministic replay artifact from the persisted counterexample; bodyless and does not execute
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/runs/:runId/replays/:replayId/run` — explicitly execute the persisted replay artifact in a fresh networkless-worker workspace; retries preserve the artifact and receive new replay-run IDs
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/runs/:runId/replays/:replayRunId/reviews` — confirm relevance of that successfully reproduced replay run and invoke centralized lifecycle evaluation

Every invariant identifier is UUID-validated and the service verifies the complete hypothesis → proposal → invariant run → replay artifact/run relationship against persisted server state. Replay endpoints never accept counterexample values, handler actions, plans, commit/compiler identity, commands, environment, or Forge arguments. All invariant action POSTs read at most 1,024 actual body bytes and require zero body bytes; declared or actual oversized input fails before service/provider use.

Run history returns an authoritative persisted `engine` (`foundry` or `echidna`) and normalized `propertyOutcome`/`hypothesisRelation` evidence. New runs also persist their proposal ID. Echidna replay artifacts record `sourceEngine`, source invariant run ID, and canonical counterexample hash. Historical Foundry rows resolve as Foundry after migration; their proposal association remains hash based if the old row did not store an ID. The app has no engine enum body, execution configuration body, or combined-engine action.

Public history refuses contradictory persisted run engine, canonical plan, compiler, evidence, or Echidna seed. A historical run is associated with a proposal by plan hash only when exactly one proposal matches; ambiguous associations remain unset. Replay history refuses mismatched source engine, source run, proposal, replay-plan hash, or counterexample hash. These checks do not rewrite stored records.

Invalid state transitions fail without rewriting prior history. Proposal generation, validation, invariant execution, replay generation, failed/refused/not-reproduced replay, and counterexample discovery alone never set a hypothesis to `verified`. Only authoritative supporting evidence created by explicit relevance review enters the centralized lifecycle authority. The application is a single-user local service without application authentication; expose it only on a trusted local interface.

## Health

- `GET /api/health` — database, AI-configuration visibility, and tool health

### Strategy-aware planning UI (v0.2.2 Milestone 1, release-ready)

A compatible Verification option sends only the selected strategy in the route path and no request body. The server reloads persisted evidence and reassesses compatibility. The structured response includes its immutable attempt ID and reviewable result; invariant responses include the persisted proposal ID, selected-strategy provenance and canonical mode. Generation never executes. Current compatibility rejection uses `strategy_not_compatible` or `strategy_compatibility_unknown` with bounded reasons; the page reloads the options. Concrete planning failures remain saved as `failed` attempts or proposals with bounded failure codes. The existing manual generation, validation, execution, replay and review endpoints remain available.
### Explicit authoritative planning reuse (v0.2.2 Part 2B-1A)

`POST /api/hypotheses/:hypothesisId/verification-target/reuse/structured/:attemptId` and `POST /api/hypotheses/:hypothesisId/verification-target/reuse/invariant/:proposalId` accept an empty body and no query parameters. The path IDs are selectors only. A successful request returns `201` with the new `attempt` or `proposal`; its ID belongs to the requested hypothesis and its origin is `reused`. The new artifact includes bounded reuse source/target identity and a fresh authoritative source-closure fingerprint. It has no inherited execution, evidence, validation, replay, or lifecycle state.

The server reloads current persisted evidence, target, strategy, scan, compilation, alignment, and source snapshot state on each POST. It recomputes the verified raw-byte closure fingerprint and checks the original generation-time fingerprint, exact scan/commit/compiler identity, target membership, selected strategy, and invariant mode/property target. Echidna concrete compatibility is checked again. Reuse never calls AI or executes verification. Unsupported profiles and historical null-fingerprint artifacts cannot be reused. Failures return bounded `reuse_*` codes with `400`, `404`, `409`, or `500`; no automatic generation fallback occurs. The explicit client action is described below.

### Explicit reuse client (v0.2.2 Part 2B-1B)

The hypothesis page shows **Reuse plan** only for advisory `eligible` candidates returned by `GET /api/hypotheses/:hypothesisId/verification-target`. Each action sends the same bodyless POST described above; browser eligibility is never admission authority. After success, the new artifact is selected in the existing review UI with validation pending. After a bounded rejection, the browser displays a safe message for the selected candidate and refreshes the verification-target GET once. It sends no plan, source, strategy, compiler, fingerprint, property, provider, or execution fields and starts no generation, validation, or worker request. The user may separately select direct Generate plan, Validate plan/proposal, and an explicit execution control.

## Impact Lab Phase A2 internal API

`GET /api/impact/rpc-configs` returns enabled `{id, chainId, network}` entries only. `POST /api/impact/sessions` accepts exactly one `findingId` or `hypothesisId`, `rpcConfigId`, exact numeric `forkBlock`, and 1–20 `targetContracts` addresses. It rejects raw URLs, executable paths, argv and keys. `GET /api/impact/sessions/:id` returns safe identity/status; `DELETE` stops an active session; `POST /api/impact/sessions/:id/recreate` explicitly rebuilds a stopped/failed session from saved identity. Responses include block hash and target `sha256:` bytecode hashes when resolved, but omit provider URL/ref, local execution endpoint, process data and keys. B1/C1 PoC and state routes are described above.

Phase A3's internal `createPoCRuntime({sessionId})`, `inspect(runtimeId)`, and `destroy(runtimeId)` service methods are not browser routes. Creation rejects extra keys such as RPC URL, image, command, argv, or environment. The server resolves the current guarded fork handle and fixed image ID. This runtime executes only ContractHunter's harmless network probe; no Solidity, Forge or vulnerability PoC is accepted.
