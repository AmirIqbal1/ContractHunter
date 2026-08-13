# ContractHunter

ContractHunter is a locally hosted smart-contract security analysis workstation. V0.1.2 accepts an authorised GitHub Solidity repository, resolves and prepares its Solidity compiler requirements, and performs real static analysis with Slither without executing repository setup scripts.

> [!WARNING]
> **ContractHunter must only be used against smart contracts and repositories the user is authorised to analyse. Repository content is treated as untrusted.**

## V0.1.2 — Automatic Solidity Compiler Management

- Dark, responsive dashboard, new-hunt flow, scan progress, filtered findings, and finding detail pages
- GitHub HTTPS repository validation with optional branch, tag, or commit selection
- Exact scanned commit capture and passive Foundry/Hardhat detection
- SQLite persistence through Drizzle ORM
- Lightweight in-process background job runner with interrupted-job recovery
- Real Slither static analysis behind an extensible `Scanner` interface
- Tolerant Slither JSON parsing, repository-relative source locations, and detector/location deduplication
- Per-scan scanner availability, execution status, finding count, and duration reporting
- Static compiler detection from strict default-profile `foundry.toml` data or Solidity pragmas
- Automatic trusted solc installation through `solc-select`, persistent compiler caching, and version verification
- Compatible multi-compiler resolution with a configurable safety limit
- Validated JSON endpoints and a container health endpoint
- Docker-first operation with a persistent `/data` volume and non-root runtime

The production pipeline clones the repository, detects its framework, discovers Solidity requirements, downloads missing official compilers through `solc-select`, caches them under the persistent data directory, verifies the selected compiler, and invokes Slither with that compiler configuration. Findings are normalised and displayed throughout the dashboard and review pages. The mock scanner remains only as an automated test fixture. Scan depth is stored but does not change behaviour in V0.1.2.

## Architecture

The Next.js process hosts the UI, route handlers, and a deliberately small in-process job runner. Scan orchestration depends on scanner and persistence interfaces rather than external queue infrastructure. SQLite stores scans and findings; cloned repositories live in a unique scan directory under the configured repository root.

```text
apps/web/              Next.js UI, API routes, and job-runner adapter
packages/core/         Domain models, Zod schemas, config, git safety, state machine
packages/db/           Drizzle schema and SQLite repository functions
packages/scanners/     Compiler manager, Slither integration, bounded process runner, parsers
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
# Edit the data, repository, database, and tool-home paths so they are absolute.
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

- Repository content is hostile input. ContractHunter never runs package managers, dependency installers, project scripts, Hardhat configuration, Forge commands, Makefiles, or shell scripts to resolve compilers.
- `foundry.toml` is parsed strictly as TOML data. Solidity source pragmas are inspected statically with comments ignored. Symlinks escaping the scan workspace and generated output directories are excluded.
- Compiler installation is a narrow trusted operation: only resolver-produced stable version strings are passed to `solc-select` using fixed argument arrays, bounded output, and timeouts. Compiler selection is child-process-local and does not mutate global application state.
- Git is launched directly with argument arrays, terminal prompting disabled, and a bounded timeout. URLs are restricted to GitHub HTTPS owner/repository paths; refs are validated before use.
- Every clone destination is derived from a generated scan UUID and checked to remain below `REPOSITORY_DIR`.
- Errors returned to the UI are length-limited, flattened, and stripped of URL credentials. Secrets should not be placed in repository URLs or refs.
- ContractHunter is a single-user local tool. It has no authentication and should not be exposed directly to an untrusted network.
- The in-process runner is intentionally single-instance infrastructure. Active scans are marked failed as interrupted after a process restart; jobs are not resumed.
- Slither may invoke its supported Solidity compilation tooling to analyse source, but ContractHunter does not execute repository setup commands.
- The production container runs as the unprivileged `node` user, drops Linux capabilities, and persists only `/data`.

## Current dependency limitation

Missing project dependencies are not installed automatically. The repository must already contain the imports required for compilation. ContractHunter will not run `npm install`, `yarn`, `pnpm`, `forge install`, or repository-provided setup scripts.

## Roadmap

Future scanner implementations may integrate Aderyn, AI-assisted review, Foundry proof-of-concepts, fuzzing, and Echidna. Those integrations, dependency installation, bounty scraping, live chain access, wallets, authentication, and automatic PoCs are intentionally outside V0.1.2.
