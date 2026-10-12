# ContractHunter

ContractHunter is evolving from a locally hosted smart-contract scanner into a **Web3 security research environment**. Its direction is to help beginners and experienced researchers understand large protocols, find important contracts and relationships, inspect attack surface, investigate findings, verify hypotheses, and safely reproduce impact on a local fork. The research path is **understand → investigate → verify → reproduce → explain impact**.

**Core product priorities:** **#1 Protocol Map** and **#2 Contract Explorer**, both with initial research interfaces implemented. These are core capabilities for understanding a protocol before and during vulnerability research. The design principle is: *Do not hide Web3 security complexity from beginners — make it understandable visually while keeping the real technical information available.* The source-order Function Explorer is implemented; deeper security views remain planned.

## Impact Lab Phase D1 (unreleased v0.3)

Impact Lab foundations are implemented through A1 fork lifecycle and safety, A2 read-only upstream forking, A3 isolated PoC runtime, B1 reviewed manual Forge execution, C1 PRE/POST state capture and diff, and D1 local transaction traces. Reviewed PoCs run only against verified local Anvil forks. There is no autonomous PoC generation, live-chain submission, asset-flow inference, or automatic vulnerability verification. See [Impact Lab](docs/impact-lab.md).

Use it only with repositories and contracts you are authorised to analyse. Repository content is treated as hostile input.

## Features

- Source-linked Protocol Map with contract relationships, filters and finding references
- Source-linked Contract Explorer with entry points, callers/callees, findings and review cues
- Visual Function Explorer with source-order operations, exact links and partial-analysis warnings
- Slither + Aderyn static analysis
- Deterministic cross-scanner investigations
- Optional AI protocol analysis and specialist security review
- Ranked vulnerability hypotheses
- Structured local verification with deterministic Foundry harnesses
- Foundry fuzz testing and stateful invariant testing, with Echidna as a manually selected second local engine for a narrower stateful subset
- Deterministic counterexample replay with explicit relevance review
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

**v0.3 — Fork & Impact Engine / Impact Lab** · In development; Phase D1 local trace capture implemented, not released

Phase A1 established managed fork lifecycle and safety; A2 added the read-only upstream boundary and exact deployment identity; A3 proved real Anvil compatibility and isolated the PoC runtime. B1 runs reviewed manual Forge PoCs; C1 captures selected state changes; D1 records bounded local call traces. Deeper impact interpretation and visual investigation remain planned after the ProtocolGraph foundation.

**Next active major track — Protocol Intelligence:** Phases 1–5 now include the ProtocolGraph, Repository Mapper, static graph, **#1 Protocol Map**, and **#2 Contract Explorer**. Open the Map from a completed hunt, select a contract, then open its Explorer for source-linked structure and findings. **Phase 6 Function Explorer** is implemented. **Phase 7 Security Views** are next. See [Protocol Map architecture](docs/protocol-map.md).

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
OPENAI_MODEL=gpt-5.6-luna
```

Pricing values are configurable estimates, not an official invoice; recheck them when changing models. See [full configuration](docs/configuration.md).

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
