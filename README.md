# ContractHunter

ContractHunter is a locally hosted smart-contract security analysis workstation. V0.1 accepts an authorised GitHub Solidity repository, clones an exact revision without executing repository code, detects Foundry or Hardhat, and passes the repository through an extensible scanner pipeline.

> [!WARNING]
> **ContractHunter must only be used against smart contracts and repositories the user is authorised to analyse. Repository content is treated as untrusted.**

## V0.1 capabilities

- Dark, responsive dashboard, new-hunt flow, scan progress, filtered findings, and finding detail pages
- GitHub HTTPS repository validation with optional branch, tag, or commit selection
- Exact scanned commit capture and passive Foundry/Hardhat detection
- SQLite persistence through Drizzle ORM
- Lightweight in-process background job runner with interrupted-job recovery
- Extensible `Scanner` interface and a harmless mock scanner for end-to-end testing
- Validated JSON endpoints and a container health endpoint
- Docker-first operation with a persistent `/data` volume and non-root runtime

The mock scanner deliberately returns obvious `[MOCK]` findings. It does not inspect Solidity and its output is not a security assessment. Scan depth is stored but does not change behaviour in V0.1.

## Architecture

The Next.js process hosts the UI, route handlers, and a deliberately small in-process job runner. Scan orchestration depends on scanner and persistence interfaces rather than external queue infrastructure. SQLite stores scans and findings; cloned repositories live in a unique scan directory under the configured repository root.

```text
apps/web/              Next.js UI, API routes, and job-runner adapter
packages/core/         Domain models, Zod schemas, config, git safety, state machine
packages/db/           Drizzle schema and SQLite repository functions
packages/scanners/     Scanner implementations (mock only in V0.1)
data/                  Local database and cloned repositories (gitignored)
Dockerfile             Multi-stage, non-root production image
docker-compose.yml     Application and persistent data volume
```

## Run with Docker

Docker and Docker Compose are the only prerequisites.

```bash
docker compose up --build
```

Open <http://localhost:3000>. Data persists in the `contracthunter-data` volume. The health endpoint is available at <http://localhost:3000/api/health>.

## Local development

Node.js 20 or newer, npm, and Git are required.

```bash
cp .env.example .env
# Edit the three paths in .env so they are absolute paths on this machine.
npm install
npm run dev
```

Without `.env`, development defaults to the repository's local `data/` directory.

Quality commands:

```bash
npm test
npm run lint
npm run typecheck
npm run build
npm start
```

## API

- `POST /api/scans` — validate and enqueue a scan
- `GET /api/scans` — list scans
- `GET /api/scans/:id` — retrieve a scan and its findings
- `GET /api/findings` — list findings; accepts `scanId`, `severity`, `source`, and `status`
- `GET /api/findings/:id` — retrieve one finding
- `GET /api/health` — process and database health

## Security assumptions

- Repository content is hostile input. V0.1 never runs package managers, build tools, project scripts, Solidity compilers, or commands derived from repository files.
- Git is launched directly with argument arrays, terminal prompting disabled, and a bounded timeout. URLs are restricted to GitHub HTTPS owner/repository paths; refs are validated before use.
- Every clone destination is derived from a generated scan UUID and checked to remain below `REPOSITORY_DIR`.
- Errors returned to the UI are length-limited, flattened, and stripped of URL credentials. Secrets should not be placed in repository URLs or refs.
- ContractHunter is a single-user local tool. It has no authentication and should not be exposed directly to an untrusted network.
- The in-process runner is intentionally single-instance infrastructure. Active scans are marked failed as interrupted after a process restart; jobs are not resumed.
- The production container runs as the unprivileged `node` user, drops Linux capabilities, and persists only `/data`.

## Roadmap

Future scanner implementations may integrate Slither, Aderyn, AI-assisted review, Foundry proof-of-concepts, fuzzing, and Echidna. Those integrations, bounty scraping, live chain access, wallets, authentication, and automatic PoCs are intentionally outside V0.1.
