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

## Health

- `GET /api/health` — database, AI-configuration visibility, and tool health
