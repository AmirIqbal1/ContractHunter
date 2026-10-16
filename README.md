# ContractHunter

ContractHunter is a **Web3 security research environment**. The released v0.2.2 workflow covers scanning, investigations and deterministic local verification. The unreleased v0.3.0 candidate adds static protocol understanding, reviewed local-fork reproduction, bounded impact analysis and evidence/report export. Static findings, local execution and reports have distinct authority; none establishes protocol safety or bounty eligibility on its own.

## Impact Lab Phase G2 — Bug-Bounty Report and Export (implemented, unreleased v0.3)

A finalized G1 Evidence Package can now create a draft `contracthunter-bounty-report-v1` report under `contracthunter-bounty-report-ruleset-v1`. The report model and Markdown renderer use only that verified package. A researcher can edit bounded plain-text title, summary, impact statement, reproduction note and context fields; evidence facts remain read only. Finalized report revisions are immutable and bind the package content and manifest hashes. Download deterministic UTF-8 Markdown, copy the exact download text, or use the clean browser print view to save a PDF. G2 runs no PoC, replay, RPC, scanner or AI. **Impact Lab Phase G is implemented. v0.3.0 has passed automated release hardening and awaits manual browser review and release.** The trusted production Impact PoC worker rebuild and disposable local-fork B1–E1/G1/G2 smoke passed; v0.3.0 is not released.

## Impact Lab Phase G1 — deterministic Evidence Package (unreleased v0.3)

An exact finding, investigation, or hypothesis can now create a draft Evidence Package from persisted scan and Impact Lab records, then explicitly finalize an immutable JSON package. The server resolves canonical IDs, freezes bounded source excerpts, static paths/graph context, reviewed PoC and fork identity, local execution, C1/D1/E1 evidence, reviewed F1 roles, and selected F2 replay evidence when present. The manifest, provenance links, capability states, warnings, fixed limitations, and SHA-256 hashes make missing or partial evidence visible. Packaging reads persisted evidence only; it does not run a PoC, replay, worker, fork, or RPC. **Impact Lab G1 and G2 are implemented.** Release hardening has verified the production worker through a disposable local-fork smoke; final automated release checks passed; the manual browser walkthrough remains outstanding before publication.

## Impact Lab Phase F2B — visual bounded replay (unreleased v0.3)

A reviewed F2A run now has a read-only result page at `/hunts/:scanId/impact/executions/:executionId/assets/scenarios/:scenarioId/replay/:planId/runs/:runId`. Independent mode shows exact matches and variation against the original reviewed reproduction without summing baseline repeats. Cumulative mode shows per-asset completed movement, direct role transfers and observed PRE/POST resource evolution, with an integer-safe chart and exact table. Iteration links open its runtime execution, state observations, Asset Flow and canonical mapped Explorer destinations. Stop reasons, partial evidence, local gas cost and final-reset state remain explicit. The page adds no replay controls, projection, pricing, TVL, severity, AI or lifecycle authority. **Impact Lab Phase F is implemented for reviewed bounded scenario analysis. Next: v0.3.0 Release Hardening.**

## Impact Lab Phase F2A — bounded scenario replay (unreleased v0.3)

An exact reviewed F1 scenario can create a reviewed replay plan for **2–5 local repetitions** of its existing reviewed B1 PoC. Independent mode resets to the captured baseline before each iteration and reports consistency without summing movements. Cumulative mode keeps evolving local state and reports only observed per-asset movement across completed iterations. Every iteration retains its own B1 execution, C1/D1 evidence, E1 asset accounting and F1 role accounting. Plans and runs are separate; finalized plans and iterations remain immutable. Replay uses the existing isolated worker and local fork controller, stops on unexpected outcomes, and always attempts final reset or stops the fork. It adds no source editing, arbitrary transaction input, resource top-up, fiat valuation, severity, profit claim, unlimited repeatability claim or maximum-drain search. **F2B and G2 are implemented.**

## Impact Lab Phase F1 — reviewed scenario roles (unreleased v0.3)

From an E2 Asset Flow page, **Create Impact Scenario** starts a draft with every E1 participant unassigned. A researcher explicitly marks scenario-subject, protocol, or counterparty participants, reviews a deterministic per-asset preview, and confirms an immutable reviewed revision. The scenario binds to one exact execution, E1 content hash, accounting ruleset, and existing finding/hypothesis reference. Changed E1 evidence makes prior reviews historical and requires a new draft and review. Reviewed ScenarioImpact shows raw-unit role positions, direct ledger-backed transfers, unassigned-flow warnings, inherited reconciliation, and local execution cost separately. It does not infer attacker/victim status, profit, protocol loss, severity, prices, repeatability, or maximum drain. **Phase F2A and F2B are implemented; G2 report/export is implemented.**

## Impact Lab Phase E — implemented (unreleased v0.3)

The read-only **Asset Flow** view is available from an eligible Impact execution at `/hunts/:scanId/impact/executions/:executionId/assets`. It presents E1 committed movements, a separate attempted/reverted layer, exact raw-unit ledger and net/gross positions, PRE/POST reconciliation, observed assets and participants, warnings, and local execution cost separately. Select one execution and transaction at a time; canonical accounting remains server-owned. Static Money Flow is source-backed potential movement, while observed Asset Flow is evidence from this isolated local reproduction. Net movement is not profit or loss. Phase F1 reviewed roles are implemented; Phase F2A bounded replay is implemented; F2B visualization is implemented. See [Impact Lab](docs/impact-lab.md).

## Impact Lab Phase E1 — deterministic asset-flow accounting (unreleased v0.3)

The read-only `contracthunter-asset-flow-v1` engine derives exact local-fork native value movements and committed receipt-log token transfer facts from one reviewed Impact execution. It keeps attempted/reverted flows, PRE/POST net observations, net/gross raw-unit positions, reconciliation and unavailable execution gas cost separate. The scan-scoped API is `/api/scans/:scanId/impact/poc-executions/:executionId/asset-flow`. Token standards without authoritative classification remain unresolved. E2 renders this result, F1 adds reviewed scenario roles, and F2B renders bounded replay. Profit, protocol loss, severity, and fiat valuation are outside this implementation. See [Impact Lab](docs/impact-lab.md).

ContractHunter helps beginners and experienced researchers understand large protocols, find important contracts and relationships, inspect attack surface, investigate findings, verify hypotheses, and reproduce reviewed PoCs on an isolated local fork. The research path is **understand → investigate → verify → reproduce → explain impact**.

**Core product priorities:** **#1 Protocol Map** and **#2 Contract Explorer**, both with initial research interfaces implemented. These are core capabilities for understanding a protocol before and during vulnerability research. The design principle is: *Do not hide Web3 security complexity from beginners — make it understandable visually while keeping the real technical information available.* The source-order Function Explorer and deterministic Security View models are implemented; interactive Security Views are implemented.

## Protocol Intelligence Phase 10 — Dynamic Impact Lab Overlays (unreleased v0.3)

The read-only, deterministic Impact Overlay model now combines exact reviewed local Impact Lab execution evidence with a separate static ProtocolGraph and Investigation Path comparison. It preserves local transactions, D1 observed calls/logs and C1 state observations without changing static facts or finding authority. Contract/function alignment remains unresolved in production where no authoritative deployed-bytecode-to-source witness exists. Phase 10B now renders Static Investigation, Observed Execution and Compare views, local call trees, transaction-specific logs and PRE/POST state observations. See [Impact Lab](docs/impact-lab.md).

## Impact Lab Phase D1 (unreleased v0.3)

Impact Lab foundations are implemented through A1 fork lifecycle and safety, A2 read-only upstream forking, A3 isolated PoC runtime, B1 reviewed manual Forge execution, C1 PRE/POST state capture and diff, D1 local transaction traces, and E1 read-only asset accounting. Reviewed PoCs run only against verified local Anvil forks. There is no autonomous PoC generation, live-chain submission, profit/loss inference, or automatic vulnerability verification. See [Impact Lab](docs/impact-lab.md).

Use it only with repositories and contracts you are authorised to analyse. Repository content is treated as hostile input.

## Features

- Source-linked Protocol Map with contract relationships, filters and finding references
- Security Views and Start Here guidance with deterministic audit-interest cues
- Source-linked Contract Explorer with entry points, callers/callees, findings and review cues
- Visual Function Explorer with source-order operations, exact links and partial-analysis warnings
- Static Investigation Paths for findings, investigations and hypotheses, with exact source and provenance links
- Slither + Aderyn static analysis
- Deterministic cross-scanner investigations
- Optional AI protocol analysis and specialist security review
- Ranked vulnerability hypotheses
- Structured local verification with deterministic Foundry harnesses
- Foundry fuzz testing and stateful invariant testing, with Echidna as a manually selected second local engine for a narrower stateful subset
- Deterministic counterexample replay with explicit relevance review
- Reviewed local-fork PoCs, state diffs, transaction traces and runtime overlays
- Asset Flow, reviewed scenario accounting and bounded independent/cumulative replay
- Immutable Evidence Packages and deterministic bug-bounty Markdown reports with a print view
- API cost estimates and recorded usage visibility
- Local-first, Docker-first operation

## Workflow

```text
Repository → Slither + Aderyn → Investigations → Static scan complete
          → optional AI Protocol Analysis → optional AI Security Review
          → Hypotheses → structured Verification or reviewed Invariant Proposal
          → bounded execution → deterministic replay → relevance review
```

Static scanning does not use OpenAI tokens. AI stages are optional and manual. AI hypotheses are not verified vulnerabilities. Local verification is explicit and fail-closed. Bounded fuzzing is not formal proof.

## Milestones

**v0.2.0 — Executable invariants** · Released

Deterministic Foundry fuzz/property and stateful invariant testing, AI semantic invariant proposals, deterministic counterexample replay, explicit relevance review, and authoritative dynamic evidence.

**v0.2.1 — Echidna invariant engine** · Released

- **Milestone 1 — Engine foundation:** reproducible patched Echidna 2.3.3, networkless worker execution, a deterministic stateful invariant subset, strict structured output, and reuse of the existing replay pipeline.
- **Milestone 2 — Explicit engine workflow:** manual Foundry/Echidna selection, persisted engine provenance, compatibility reporting, Echidna run history, and Echidna-origin deterministic replay.
- **Milestone 3 — Release hardening:** migration hardening, fresh-install validation, public workflow QA, malformed-output and tamper regression coverage.

Echidna supports a bounded compatible subset; bounded success means no counterexample was found within the configured budget, not that safety is proven. A counterexample alone does not verify a vulnerability.

**v0.2.2 — Smarter verification** · Released

Deterministic verification options and strategy-aware planning, conservative target grouping with representative navigation, and explicit plan reuse. Supported plain-profile scans preserve immutable source snapshots, authoritative compilation provenance, and raw-byte source-closure fingerprints. Compatibility and grouping are advisory; a reused plan needs fresh review and validation before separate execution, with no inherited evidence or lifecycle state. Authoritative source and reuse support is limited to `plain-solidity-exact-pragma-v1`; broader Foundry and Hardhat projects may be scanned but are not yet authoritative-supported.

**v0.3.0 — Protocol Intelligence + Impact Lab** · Release candidate ready for manual review; not released

Phase A1 established managed fork lifecycle and safety; A2 added the read-only upstream boundary and exact deployment identity; A3 isolated the PoC runtime. B1 runs reviewed manual Forge PoCs; C1 captures selected state changes; D1 records bounded local call traces. E1 derives deterministic asset accounting and E2 renders it. F1 adds reviewed scenario roles; F2 adds bounded replay and visual analysis; G1 adds immutable evidence packages; G2 adds deterministic bug-bounty reports and Markdown export.

**Protocol Intelligence:** Phases 1–10 are implemented in unreleased development. Phase 9A derives bounded static Investigation Paths; Phase 9B renders them from finding, investigation and hypothesis detail. Phase 10A derives a separate observed local execution/state read model. Open a completed hunt with a finalized static graph, then choose **Show Me Where To Start** or **Open Protocol Map**, or open a finding and select **View Investigation Path**. Static paths are source-backed research context, not proof of execution or exploitability. Impact Lab Phases E–G1 and G2 are implemented. See [Protocol Map architecture](docs/protocol-map.md).

See the [full roadmap](docs/roadmap.md) and [Impact Lab design](docs/impact-lab.md) for details.

## Future

Possible future work includes per-stage AI models, additional scanners, Vyper, benchmark/regression scoring, local LLM support, CI/PR review mode, and broader Echidna semantics after equivalence and replay safety are proven.

## Quick start

Prerequisites: Docker and Docker Compose.

```bash
cp .env.example .env
docker compose build
docker compose up -d
```

`OPENAI_API_KEY` may remain empty unless AI features are wanted. Open <http://localhost:3000>. Health is available at <http://localhost:3000/api/health>.

```bash
docker compose down
```

## Common AI configuration

```dotenv
AI_ENABLED=true
OPENAI_API_KEY=
OPENAI_MODEL=gpt-6-luna
```

GPT-6 Luna is the optional manual AI default. Standard pricing estimates use the model’s short and long context rates; cache usage is not yet persisted, so displayed costs are estimates rather than invoices. See [full configuration](docs/configuration.md).

## Local development

Prerequisites: Node.js 20+, npm, and Git. Local verification additionally needs the supported Linux isolation and Foundry toolchain.

```bash
cp .env.example .env
npm install
npm run dev
```

See [development notes](docs/development.md) for quality checks, Docker details, data layout, and release smoke tests. `.env` must never be committed.

## Current limitations

AI remains optional/manual and hypotheses are not automatically verified. Local verification supports only a bounded structured language and requires the trusted compiler cache plus fail-closed Linux isolation. See the [roadmap](docs/roadmap.md) and [security model](docs/security-model.md).

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Configuration](docs/configuration.md)
- [API reference](docs/api.md)
- [Development](docs/development.md)
- [Release history](docs/release-history.md)
- [Roadmap](docs/roadmap.md)
- [Impact Lab design](docs/impact-lab.md)
- [AI handoff](docs/ai-handoff.md)
