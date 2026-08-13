# ContractHunter

ContractHunter is a locally hosted smart-contract security analysis workstation. V0.1.5 safely prepares an authorised Solidity repository, combines Slither and Aderyn, and builds a prioritised investigation queue from their evidence.

> [!WARNING]
> **ContractHunter must only be used against smart contracts and repositories the user is authorised to analyse. Repository content is treated as untrusted.**

## v0.1.5 — Cross-scanner correlation

ContractHunter now groups likely related Slither and Aderyn findings into Investigations. Correlation is deterministic and location-led: file, contract, function, source ranges, an explicit detector taxonomy, and limited title similarity contribute to an explainable score. A stable representative-based grouping rule deliberately avoids broad transitive merging.

Independent scanner agreement increases investigation confidence and priority, but never raises the scanner-provided severity and never automatically verifies a candidate. Static-only confidence is capped below 90. Every raw finding remains available as immutable scanner evidence.

- **Finding** = one normalized raw scanner output.
- **Investigation** = ContractHunter's grouped candidate vulnerability and review priority.
- **Verified** = a manual human status in this release; automated verification comes later.

## v0.1.4 — Aderyn integration

ContractHunter now runs two independent Solidity static analyzers:

- Slither
- Aderyn

Each engine can detect different vulnerability patterns and provide useful independent evidence. Findings retain their scanner source, and a failure in one scanner does not discard successful results from the other. If both scanners fail, the hunt fails; if one succeeds, the hunt completes with the failed scanner clearly identified.

Multiple scanners reporting similar issues does **not** mean ContractHunter has verified a vulnerability.

## v0.1.3 — Safe dependency preparation

ContractHunter safely prepares common public Solidity dependencies before compiler resolution and Slither analysis:

- Pinned Git submodules declared with approved HTTPS GitHub URLs
- npm dependencies captured by `package-lock.json` or `npm-shrinkwrap.json`
- Iterative validation of nested submodules before each checkout level
- Deterministic `npm ci` with lifecycle scripts, audit, and funding requests disabled
- Isolated npm home, cache, and configuration without host credentials
- Bounded dependency command output and timeouts

Repository install scripts are intentionally never executed. Unusual dependency sources fail preparation instead of weakening the security policy.

Supported package-manager scope:

- npm with `package-lock.json` or `npm-shrinkwrap.json`
- Approved HTTPS Git submodules pinned by the repository commit

Not yet supported:

- Yarn or pnpm
- Arbitrary setup scripts or Makefiles
- `forge install` fallback
- npm projects without a supported lockfile

## Automatic Solidity compiler management

- Dark, responsive dashboard, new-hunt flow, scan progress, filtered findings, and finding detail pages
- GitHub HTTPS repository validation with optional branch, tag, or commit selection
- Exact scanned commit capture and passive Foundry/Hardhat detection
- SQLite persistence through Drizzle ORM
- Lightweight in-process background job runner with interrupted-job recovery
- Real Slither and Aderyn static analysis behind an extensible `Scanner` interface
- Tolerant Slither JSON parsing, repository-relative source locations, and detector/location deduplication
- Independent per-scanner availability, execution status, error, finding count, and duration reporting
- Static compiler detection from strict default-profile `foundry.toml` data or Solidity pragmas
- Automatic trusted solc installation through `solc-select`, persistent compiler caching, and version verification
- Compatible multi-compiler resolution with a configurable safety limit
- Validated JSON endpoints and a container health endpoint
- Docker-first operation with a persistent `/data` volume and non-root runtime

The production pipeline clones the repository, detects its framework, prepares approved pinned submodules and lockfile-based npm dependencies, resolves compiler requirements, invokes Slither followed by Aderyn, and then correlates all successful static-analysis output. Scan depth is stored but does not change behaviour in V0.1.5.

## Architecture

The Next.js process hosts the UI, route handlers, and a deliberately small in-process job runner. Scan orchestration depends on scanner and persistence interfaces rather than external queue infrastructure. SQLite stores scans and findings; cloned repositories live in a unique scan directory under the configured repository root.

```text
apps/web/              Next.js UI, API routes, and job-runner adapter
packages/core/         Domain models, Zod schemas, config, git safety, state machine
packages/db/           Drizzle schema and SQLite repository functions
packages/scanners/     Dependency/compiler managers, Slither/Aderyn scanners and parsers
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
- `GET /api/investigations` — list ranked investigations; accepts scan, severity, status, minimum-confidence, and source-count filters
- `GET /api/investigations/:id` — retrieve an investigation and its raw evidence
- `PATCH /api/investigations/:id` — manually update investigation status
- `GET /api/health` — process and database health

## Security assumptions

- Repository content is hostile input. Dependency preparation is limited to pinned approved Git submodules and `npm ci` with lifecycle scripts disabled. ContractHunter never runs repository scripts, Hardhat configuration, Forge commands, Makefiles, or shell commands.
- `.gitmodules`, package manifests, and lockfiles are parsed as data. Submodule paths cannot escape the repository; only credential-free HTTPS hosts on the configured allowlist are accepted. Nested modules are validated before their level is fetched.
- npm uses an isolated configuration and cache, does not inherit host credentials, and rejects local, directory, SSH, unusual Git-host, and arbitrary remote-tarball dependencies. Repository `.npmrc` settings cannot override the policy.
- `foundry.toml` is parsed strictly as TOML data. Solidity source pragmas are inspected statically with comments ignored. Symlinks escaping the scan workspace and generated output directories are excluded.
- Compiler installation is a narrow trusted operation: only resolver-produced stable version strings are passed to `solc-select` using fixed argument arrays, bounded output, and timeouts. Compiler selection is child-process-local and does not mutate global application state.
- Git is launched directly with argument arrays, terminal prompting disabled, and a bounded timeout. URLs are restricted to GitHub HTTPS owner/repository paths; refs are validated before use.
- Every clone destination is derived from a generated scan UUID and checked to remain below `REPOSITORY_DIR`.
- Errors returned to the UI are length-limited, flattened, and stripped of URL credentials. Secrets should not be placed in repository URLs or refs.
- ContractHunter is a single-user local tool. It has no authentication and should not be exposed directly to an untrusted network.
- The in-process runner is intentionally single-instance infrastructure. Active scans are marked failed as interrupted after a process restart; jobs are not resumed.
- Slither and Aderyn may invoke their supported Solidity compilation tooling to analyse source, but ContractHunter does not execute repository setup commands.
- The production container runs as the unprivileged `node` user, drops Linux capabilities, and persists only `/data`.

## Current dependency limitations

Only approved HTTPS Git submodules and npm lockfile installs are prepared. Yarn, pnpm, `forge install`, npm without a lockfile, private registries, credentials, arbitrary remote tarballs, and repository-provided setup scripts are intentionally unsupported.

## Roadmap

AI verification, fuzzing, PoCs, and broader dependency mechanisms remain outside V0.1.5.
