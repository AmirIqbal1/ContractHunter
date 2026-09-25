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
- `PATCH /api/hypotheses/:id` — update allowed hypothesis status
- `POST /api/hypotheses/:id/verification-plan` — generate a non-executing plan preview
- `POST /api/hypotheses/:id/verify` — validate and explicitly execute a local plan
- `GET /api/hypotheses/:id/verifications` — list verification history
- `GET /api/hypotheses/:id/invariant-proposals` — list bounded proposal and invariant-run history
- `POST /api/hypotheses/:id/invariant-proposals` — manually request one AI semantic proposal; bodyless, no execution
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/validate` — bodyless revalidation of a persisted plan and source
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/run` — bodyless explicit local run of that validated proposal through the worker
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/runs/:runId/replays` — generate a deterministic replay artifact from the persisted counterexample; bodyless and does not execute
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/runs/:runId/replays/:replayId/run` — explicitly execute the persisted replay artifact in the networkless worker
- `POST /api/hypotheses/:id/invariant-proposals/:proposalId/runs/:runId/replays/:replayRunId/reviews` — confirm relevance of a successfully reproduced replay and invoke centralized lifecycle evaluation

Replay endpoints never accept counterexample values, handler actions, plans, compilers, commands, environment, or Forge arguments. All POSTs read at most 1,024 actual body bytes and require an empty body.

Invariant routes accept no plan, command, Forge argument or configuration in request bodies. The application is a single-user local service without application authentication; expose it only on a trusted local interface. Invariant evidence does not change hypothesis status.

## Health

- `GET /api/health` — database, AI-configuration visibility, and tool health
