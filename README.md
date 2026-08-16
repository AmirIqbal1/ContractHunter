# ContractHunter

ContractHunter is a locally hosted smart-contract security analysis workstation. V0.1.8 combines deterministic static analysis, protocol understanding, security invariants, specialist AI vulnerability-hypothesis reviews, and narrowly scoped local verification.

Static analysis runs locally and completes before any optional AI work. Protocol analysis and the deeper security review are manually triggered so findings can be reviewed before spending API tokens. ContractHunter shows approximate API costs from bounded pre-run context estimates and recorded token usage using configurable input/output prices; these estimates are not an official invoice, and scanner execution itself has no OpenAI cost.

> [!WARNING]
> **ContractHunter must only be used against smart contracts and repositories the user is authorised to analyse. Repository content is treated as untrusted.**

## v0.1.8 — Safe local hypothesis verification

V0.1.8 adds an explicit, review-first verification flow for eligible hypotheses. AI can propose a bounded verification-plan preview, but generating a plan never creates a run or changes hypothesis status. The user must review the plan and separately choose **Verify locally**.

ContractHunter then creates a deterministic harness and controlled `foundry.toml` from persisted scan evidence, the exact scanned commit, an allowlisted compiler, and repository source files. It validates the workspace manifest, hashes, layout, and content fingerprint immediately before invoking a fixed Forge test command. Repository-provided scripts, commands, Foundry configuration, arbitrary Solidity, RPC endpoints, forks, wallets, FFI, and live-chain transactions are never accepted by this path.

Results are interpreted deterministically as `confirmed`, `refuted`, or `inconclusive`, with immutable verification history and structured dynamic evidence. A successful process alone cannot verify a hypothesis: only a confirmed interpretation containing supporting dynamic evidence can perform the `verified` transition. Infrastructure and parsing failures are never treated as refutation.

Execution is fail-closed and requires supported Linux isolation with working Bubblewrap network/PID namespaces, `prlimit`, Forge, and the trusted compiler cache. No host-network or unsafe fallback exists. Current verification plans are deliberately limited to zero-argument constructors and functions, uint reads, and equality/inequality assertions. Unsupported hypotheses return `not_plannable`; an AI-generated plan does not guarantee a conclusive result.

## v0.1.7 — Specialist AI security reviews

After protocol analysis, ContractHunter deterministically selects a bounded set of relevant security specialists—such as accounting, access control, state transitions, external calls, oracle, token integration, reentrancy, upgradeability, economic logic, and protocol-specific vault/lending/bridge reviewers. Each receives a deterministic, reviewer-specific subset of the source plus relevant protocol elements, invariants, and static Investigations. Requests use structured outputs, no model tools, bounded concurrency, hard request limits, and isolated failure handling.

The evidence layers have distinct meanings:

- **Static findings** are individual tool-generated Slither or Aderyn warnings.
- **Investigations** are deterministically correlated static-analysis candidates.
- **Invariants** are expected protocol security properties that are still hypotheses.
- **Hypotheses** are AI-generated explanations of how an expected property might fail.

In V0.1.7, hypotheses were **not verified vulnerabilities**. AI-created records started as `candidate`, confidence was capped at 85, and the UI could not set `verified`; executable verification was not yet part of that release. ContractHunter does not generate or run exploit scripts, use wallets, contact live chains, browse the web, or create bounty submissions.

Reviewer outputs must provide a concrete root cause, preconditions, high-level attack path, impact, exact source evidence, false-positive risks, and a safe local verification plan. Evidence is validated against the cloned repository before persistence; vague and unsupported observations are rejected. Related originals remain intact while deterministic hypothesis groups rank candidates using severity, evidence quality, static corroboration, invariant linkage, and distinct evidence classes. Agreement between multiple AI reviewers gets only a modest boost because same-provider reviewers are not independent engines.

## v0.1.6 — AI protocol understanding

After static scanning and correlation, ContractHunter can optionally use OpenAI to construct a security-focused protocol model: protocol purpose and architecture, assets, privileged roles, critical entry points and state, external dependencies, flows, trust assumptions, and concrete proposed security invariants.

AI-generated invariants are hypotheses about properties the system should preserve. They are **not verified vulnerabilities**, do not become Investigations, and start with `proposed` status for human acceptance or rejection. Confidence measures how strongly supplied repository evidence supports an interpretation—not vulnerability probability.

Repository content is untrusted data and is never treated as AI instructions. ContractHunter submits a deterministic, bounded source context with explicit secret/generated/dependency exclusions; the OpenAI request has no tools, web access, code execution, or filesystem access. Evidence references are validated locally before persistence. The current provider is OpenAI through a small provider interface; other providers are not implemented.

Configuration:

```bash
AI_ENABLED=true
OPENAI_API_KEY=your-server-side-key
OPENAI_MODEL=gpt-5-mini
AI_INPUT_COST_PER_MILLION_USD=0.25
AI_OUTPUT_COST_PER_MILLION_USD=2.00
AI_TIMEOUT_MS=180000
AI_MAX_SOURCE_BYTES=500000
AI_MAX_FILES=120
AI_MAX_FILE_BYTES=75000
AI_REVIEW_MAX_SOURCE_BYTES=300000
AI_REVIEW_MAX_FILES=80
AI_MAX_REVIEWERS=10
AI_REVIEW_CONCURRENCY=2
AI_REVIEW_TIMEOUT_MS=180000
AI_REVIEW_MAX_TOTAL_REQUESTS=12
AI_VERIFICATION_PLAN_TIMEOUT_MS=120000
AI_VERIFICATION_PLAN_MAX_SOURCE_BYTES=120000
AI_VERIFICATION_PLAN_MAX_FILES=12
```

The price defaults match the currently configured model assumption and should be checked whenever `OPENAI_MODEL` changes.

The API key remains server-side and is never stored, logged, returned by health/API routes, or included in browser code. AI failures and disabled/unconfigured AI do not invalidate successful static-analysis results. Manual reruns preserve previous analysis versions.

## v0.1.5 — Cross-scanner correlation

ContractHunter now groups likely related Slither and Aderyn findings into Investigations. Correlation is deterministic and location-led: file, contract, function, source ranges, an explicit detector taxonomy, and limited title similarity contribute to an explainable score. A stable representative-based grouping rule deliberately avoids broad transitive merging.

Independent scanner agreement increases investigation confidence and priority, but never raises the scanner-provided severity and never automatically verifies a candidate. Static-only confidence is capped below 90. Every raw finding remains available as immutable scanner evidence.

- **Finding** = one normalized raw scanner output.
- **Investigation** = ContractHunter's grouped candidate vulnerability and review priority.
- **Verified** = a manual human status in V0.1.5; automated verification was added later through the narrower V0.1.8 trust chain.

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

The production pipeline clones the repository, detects its framework, prepares approved pinned submodules and lockfile-based npm dependencies, resolves compiler requirements, invokes Slither followed by Aderyn, correlates static output, builds a protocol model and invariants, and then runs the selected specialist reviewers. AI stage failures never remove successful static results. Eligible hypotheses can subsequently enter the separate, explicit local-verification flow. Scan depth is stored but does not change behaviour in V0.1.8.

## Architecture

The Next.js process hosts the UI, route handlers, and a deliberately small in-process job runner. Scan orchestration depends on scanner and persistence interfaces rather than external queue infrastructure. SQLite stores scans and findings; cloned repositories live in a unique scan directory under the configured repository root.

```text
apps/web/              Next.js UI, API routes, and job-runner adapter
packages/core/         Domain models, Zod schemas, config, git safety, state machine
packages/db/           Drizzle schema and SQLite repository functions
packages/scanners/     Dependency/compiler managers, scanners, parsers, and isolated verification runner
data/                  Local database, cloned repositories, and verification workspaces (gitignored)
Dockerfile             Multi-stage, non-root production image
docker-compose.yml     Application and persistent data volume
```

## Run with Docker

Docker and Docker Compose are the only prerequisites for the static-analysis and review workflow.

```bash
docker compose up --build
```

Open <http://localhost:3000>. Data persists in the `contracthunter-data` volume. The health endpoint is available at <http://localhost:3000/api/health>. The supplied container does not weaken its privileges or networking to enable nested execution; local verification remains fail-closed unless the runtime provides the supported Linux isolation and Foundry toolchain.

## Local development

Node.js 20 or newer, npm, and Git are required. Local verification additionally requires Linux, Bubblewrap with working unprivileged network/PID namespaces, `prlimit`, Forge, and the trusted compiler selected for the scan.

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
- `POST /api/scans/:id/ai-analysis` — manually run or rerun configured AI protocol analysis
- `GET /api/scans/:id/ai-context` — preview bounded input size and coverage metadata without source content
- `GET /api/protocol-analyses/:id` — retrieve one historical protocol model and its invariants
- `GET /api/invariants` — list current invariants with category, impact, status, and testability filters
- `GET/PATCH /api/invariants/:id` — retrieve an invariant or manually accept/reject it
- `GET/POST /api/scans/:id/security-review` — preview cost controls or run/rerun the specialist review stage
- `GET /api/hypotheses` — list current ranked hypotheses with severity, category, reviewer, status, confidence, and evidence-class filters
- `GET/PATCH /api/hypotheses/:id` — retrieve a hypothesis or set candidate/investigating/likely-valid/rejected status
- `POST /api/hypotheses/:id/verification-plan` — generate a bounded AI-assisted plan preview without executing it
- `POST /api/hypotheses/:id/verify` — validate and execute an explicitly submitted local verification plan
- `GET /api/hypotheses/:id/verifications` — list immutable verification-run history with sanitised public evidence
- `GET /api/health` — process and database health

## Security assumptions

- Repository content is hostile input. Dependency preparation is limited to pinned approved Git submodules and `npm ci` with lifecycle scripts disabled. ContractHunter never runs repository scripts, Hardhat configuration, Makefiles, or repository-supplied shell/Forge commands.
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
- Local verification invokes only fixed Forge arguments against a ContractHunter-generated workspace. Its manifest and every source/config/harness hash are revalidated immediately before execution; the scanned repository is never the executable project or a writable sandbox mount.
- Verification receives a rebuilt environment without application credentials, proxy settings, RPC URLs, wallets, or keys. Unsupported or unavailable Linux namespace/resource isolation refuses execution rather than falling back.
- The production container runs as the unprivileged `node` user, drops Linux capabilities, and persists only `/data`.

## Current dependency limitations

Only approved HTTPS Git submodules and npm lockfile installs are prepared. Yarn, pnpm, `forge install`, npm without a lockfile, private registries, credentials, arbitrary remote tarballs, and repository-provided setup scripts are intentionally unsupported.

## Roadmap

Broader verification operations, argument-bearing calls, non-uint observations, fuzzing, Echidna, autonomous exploit/PoC generation, live-chain interaction, wallets, bounty submissions, and broader dependency mechanisms remain future work. V0.1.8 intentionally supports only reviewed, deterministic local harnesses within its narrow operation schema.
