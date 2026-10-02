# API reference

## Scans

- `POST /api/scans` — validate and enqueue a scan
- `GET /api/scans` — list scans
- `GET /api/scans/:id` — retrieve scan details and related records
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
