# ContractHunter

ContractHunter is a locally hosted smart-contract security analysis workstation combining deterministic static analysis, optional AI-assisted protocol/security reasoning, and explicit local verification.

Use it only with repositories and contracts you are authorised to analyse. Repository content is treated as hostile input.

## Features

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

**v0.2.2 — Smarter verification** · In development

Deterministic, advisory verification options; conservative verification-target grouping and representative navigation; immutable scan-time source snapshots; narrow authoritative compilation and source closures; and explicit planning reuse. Compatible means a strategy can express the current evidence, not that a vulnerability is valid. A representative is chosen deterministically for planning navigation, not as a vulnerability ranking. Reused plans require fresh review and explicit validation; execution, evidence, and lifecycle state are never inherited. Authoritative source and reuse support is limited to `plain-solidity-exact-pragma-v1`. Foundry and Hardhat authoritative support remain future work.

**v0.3 — Fork & Impact Engine / Impact Lab** · Planned

An Anvil-first, local-fork workflow for authorised researchers to reproduce candidate vulnerabilities against pinned deployed state, inspect traces and state changes, measure impact, and export reproducible evidence. Autonomous PoC generation and broader audit orchestration follow the safe engine foundation.

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
