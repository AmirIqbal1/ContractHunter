# ContractHunter

ContractHunter is a locally hosted smart-contract security analysis workstation combining deterministic static analysis, optional AI-assisted protocol/security reasoning, and explicit local verification.

Use it only with repositories and contracts you are authorised to analyse. Repository content is treated as hostile input.

## Features

- Slither + Aderyn static analysis
- Deterministic cross-scanner investigations
- Optional AI protocol analysis and specialist security review
- Ranked vulnerability hypotheses
- Explicit verification-plan generation and deterministic local verification
- API cost estimates and recorded usage visibility
- Local-first, Docker-first operation

## Workflow

```text
Repository → Slither + Aderyn → Investigations → Static scan complete
          → optional AI Protocol Analysis → optional AI Security Review
          → Hypotheses → optional Verification Plan → explicit Local Verification
```

Static scanning does not use OpenAI tokens. AI stages are optional and manual. AI hypotheses are not verified vulnerabilities. Local verification is explicit and fail-closed.

## Quick start

Prerequisites: Docker and Docker Compose.

```bash
cp .env.example .env
docker compose up --build
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
- [AI handoff](docs/ai-handoff.md)
