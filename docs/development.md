# Development

## Impact Lab F2B local manual check

1. Start ContractHunter with `npm run dev`.
2. Open a reviewed F1 scenario with an existing completed F2A replay.
3. Open the reviewed plan, then its run result.
4. Inspect the run header, source PoC hash, fork block and local-only warning.
5. Inspect an independent replay result and its exact reference/match/variation table.
6. Inspect a cumulative replay result if available.
7. Select each iteration and open its exact execution evidence.
8. Inspect per-iteration transactions, trace, state, asset and scenario accounting.
9. Select each asset; confirm unrelated assets are not combined.
10. Inspect observed resource PRE/POST evolution and the equivalent exact table.
11. Inspect final F2A cumulative movement and direct role transfers.
12. Inspect any recorded stop reason and the final reset status.
13. Follow an iteration's Observed Execution link.
14. Follow its Asset Flow and State Changes links.
15. Follow canonical Explorer/Map links where exact mapping exists.
16. Switch Beginner and Researcher presentation.
17. Confirm no projected/max-drain result or future chart line appears.
18. Confirm finding/hypothesis status and reviewed PoC remain unchanged.

No specific run ID is assumed. The F2B page itself reads persisted evidence and needs no live RPC, worker, OpenAI or transaction.

## Impact Lab F2A local manual check

Start ContractHunter with `npm run dev`. Open an existing completed Impact execution with E1 accounting and a current reviewed F1 scenario, then choose **Scenario Replay**. Inspect source hash, fork identity, reviewed roles and starting captured resources. Create a 2-iteration independent draft, confirm its local-only review statement, review and start it. Inspect the run status, each iteration's exact execution/C1/D1/E1/F1 evidence and independent match table; confirm no cumulative total is shown. Create a separate cumulative plan with 2–5 repetitions, review/start it, inspect evolving captured resources and per-asset cumulative values, then request cancellation on a run and confirm no later iteration starts. Confirm final reset, unchanged finding/hypothesis state, no PoC source change and no upstream transaction. Do not assume a hunt or execution ID. A live local fork and existing worker are needed for the manual replay; no real-chain transaction or OpenAI call is needed.

## Impact Lab F1 local manual check

Open an existing completed Impact execution with E1/E2 asset accounting. From **Asset Flow**, choose **Create Impact Scenario**. Inspect all participants before assigning roles; create a draft, explicitly assign one or more Scenario Subject participants and Protocol participants, optionally add Counterparties, save, and inspect **PREVIEW — NOT REVIEWED**. Confirm disposable senders, mapped contracts, and positive balances were not auto-assigned. Confirm roles with the manual-annotation warning, then inspect role positions, direct protocol↔subject transfers, independent assets, inherited reconciliation/warnings, and separate gas. Choose **Edit Roles** and confirm a new draft revision while the reviewed revision remains in history. Switch Beginner/Researcher; verify finding/hypothesis status is unchanged and no PoC reruns. No specific hunt or execution ID is assumed.

Run focused tests with `npx vitest run packages/core/src/impact-scenario.test.ts packages/db/src/impact-scenario.test.ts apps/web/lib/impact-scenario-server.test.ts apps/web/components/scenario-review-view.test.tsx`, then typecheck, full tests, lint, build, and the production audit attempt. No OpenAI, live RPC, blockchain transaction, or download is needed.

## Impact Lab E2 manual verification

Run `npx vitest run apps/web/components/asset-flow-view.test.tsx` for focused presentation checks. Start ContractHunter (`npm run dev` after local setup, or Docker Compose), open any hunt with a completed Impact execution and E1 accounting, open its execution, then click **Asset Flow**. Inspect committed flows and each transaction; inspect the canonical ledger, participant net movement and reconciliation; toggle attempted/reverted flows; inspect gas cost; filter by asset and participant; follow any exact mapped contract/function and runtime call links; switch Beginner/Researcher; compare with Static Money Flow. Confirm no finding, lifecycle or execution mutation occurs. Do not assume a specific hunt or execution ID. Current production evidence may leave contract/function mappings and token standards unresolved.

## Impact Lab E1 local verification

Run `npx vitest run packages/core/src/asset-flow.test.ts apps/web/lib/asset-flow-server.test.ts apps/web/app/api/scans/'[id]'/impact/poc-executions/'[executionId]'/asset-flow/route.test.ts`, then the project typecheck, test, lint and build gates and a production dependency audit attempt. For an existing reviewed local execution, request the scan-scoped `/api/scans/:scanId/impact/poc-executions/:executionId/asset-flow` endpoint. Inspect transaction-local committed and attempted entries, raw units, unknown-standard Transfer facts, PRE/POST reconciliation, unavailable gas cost, capability flags and content hash. The endpoint is rendered by the E2 Asset Flow page. No live RPC, AI, download or transaction is required.

## Phase 10B local manual check

1. Start ContractHunter with `npm run dev` and open a hunt containing an eligible finding or hypothesis with an existing persisted reviewed Impact execution.
2. Open its Investigation Path. Choose an Impact execution, then switch Static Investigation, Observed Execution and Compare.
3. Inspect the transaction selector, call tree, a mapped call if authoritative mapping exists, and a runtime-only or unmapped call if captured. Inspect Observed State Changes, including unchanged and unavailable filters.
4. Open Protocol Map with that execution and enable Observed Execution. Verify dashed observed edges and ephemeral runtime targets disappear when disabled.
5. Open Function Explorer for a mapped function, when one exists, and compare SOURCE-ORDER VIEW with OBSERVED RUNTIME ORDER. Switch Beginner/Researcher.
6. Return to the finding/hypothesis and confirm status, severity and confidence did not change. No live RPC, transaction or new PoC is needed to inspect persisted evidence.

Run `npm run typecheck`, `npm test`, `npm run lint`, `npm run build`, and attempt `npm audit --omit=dev`. Production deployment-to-source mapping remains unavailable without an authoritative witness; unmapped calls are an expected accurate result. Historical executions can show unavailable trace/state rather than an empty successful visualization.

## Impact Overlay Phase 10A

Run `npx vitest run packages/core/src/impact-overlay.test.ts` for bounded synthetic local trace/state evidence, then `npm run typecheck`, `npm test`, `npm run lint`, `npm run build`, and attempt `npm audit --omit=dev`. The read-only endpoint is `/api/scans/:scanId/impact/poc-executions/:executionId/overlay`; use an existing exact execution ID from a reviewed local PoC under the same scan. Its response is model data used by the Phase 10B visual screens. A current production response can retain runtime addresses while all graph contract/function mappings remain unresolved because deployed code hashes are not linked authoritatively to static source identities. Inspect `capabilities`, `warnings`, transaction-local blocks, observed call order and C1 unavailable states. No live RPC or transaction is needed for the synthetic tests.

## Visual Investigation Paths Phase 9B

Run `npm run dev`, open a hunt with findings and a finalized ProtocolGraph, open a finding, then select **View Investigation Path**. Inspect the selected static path and **Why This Connection Exists**; open the affected Function Explorer, return to choose local/caller/callee context, open a relevant Security View, and switch Beginner/Researcher. If a fixture exposes unresolved or truncated results, confirm the terminal/warning copy; then return to the finding. Investigation and Hypothesis details offer the same route when a finalized graph exists. No specific hunt ID is assumed. Focused test: `npx vitest run apps/web/components/investigation-path-view.test.tsx`. Run the usual typecheck, test, lint, build and production audit gates. No AI, live RPC or transaction is used.

## Investigation Paths Phase 9A

Run `npx vitest run packages/core/src/investigation-path.test.ts apps/web/lib/investigation-path-server.test.ts apps/web/app/api/scans/'[id]'/protocol-graph/investigation-paths/'[subjectType]'/'[subjectId]'/route.test.ts apps/web/app/findings/'[id]'/page.test.tsx`, then the normal audit/typecheck/test/lint/build gates. For an existing scan with a finalized graph and a finding, open that finding and follow any exact Protocol Map, Explorer and source links. The read-only path endpoint accepts that scan and finding ID; an unmapped finding returns `mapping: "unmapped"`. Investigation and Hypothesis subjects use existing exact membership. Phase 9B now renders that result. No AI, RPC, download or transaction is required. See [finding-integration-audit.md](finding-integration-audit.md).

## Beginner Mode and Start Here Phase 8B

Run `npm run dev`, open an existing hunt with finalized Protocol Intelligence data, and choose **Show Me Where To Start**. Inspect Project Overview, ranked contracts, **Why start here?**, factor evidence, recommended functions, score explanation, Security View links and source links. Switch Beginner/Researcher and confirm order/scores remain stable. Open a function and return, open a Security View, then a contract; inspect partial warnings if the scan has them. Return to Protocol Map. No scan ID is assumed. Focused UI tests: `npx vitest run apps/web/components/start-here.test.tsx`. The page is read-only and needs no AI, live RPC, downloads or transactions.

## Explainable audit priority Phase 8A

Run `npx vitest run packages/core/src/audit-priority.test.ts apps/web/app/api/scans/'[id]'/protocol-graph/audit-priority/route.test.ts`, then the normal audit/typecheck/test/lint/build gates. A completed scan with a finalized graph can request `GET /api/scans/:id/protocol-graph/audit-priority`. The response is a data model for Phase 8B, not a new page. Tests use deterministic local fixtures; no AI, RPC, downloads or blockchain transactions are required. Oracle and AccessControl coverage may remain partial under current extraction.

## Interactive Security Views Phase 7B

Start with `npm run dev`, open any completed hunt that has a finalized ProtocolGraph, then choose **Open Protocol Map**. Switch Overview and all seven Security Views, select a node or edge, inspect **Why this is shown**, use canonical Contract/Function Explorer and source/finding links, test an unresolved call warning, then return to Overview. No scan ID is assumed. Run `npx vitest run apps/web/lib/protocol-map.test.ts apps/web/components/protocol-map-security.test.tsx` for focused adapter/selector tests, followed by audit, typecheck, test, lint and build. Empty Oracle/Permissions views can be correct when extraction has no qualifying evidence. No AI, live RPC, download or transaction is needed.

## Deterministic Security Views Phase 7A

Run `npx vitest run packages/core/src/security-view.test.ts apps/web/app/api/scans/'[id]'/protocol-graph/security-views/'[view]'/route.test.ts` for focused derivation and API tests, then the normal typecheck/test/lint/build gates. A completed scan with a finalized static graph can be queried through `GET /api/scans/:id/protocol-graph/security-views/:view`; The seven projections use only persisted static facts. Oracle and AccessControl results may be empty because the current extractor does not prove those semantics. No AI, live RPC, compiler download or blockchain transaction is needed.

## Visual Function Explorer Phase 6B

Start the web app with `npm run dev` (or the documented Compose workflow). Open a completed hunt that has a finalized static graph, follow Protocol Map → Contract Explorer → a function signature, and verify the source-order warning, operation selection, immutable source links, filters, Beginner/Researcher display switch and return navigation. A supported exact-pragma scan with trusted AST facts gives the richest flow; older scans may show partial analysis or no graph. Run `npx vitest run apps/web/components/function-explorer.test.tsx apps/web/app/hunts/'[id]'/contracts/'[contractId]'/functions/'[functionId]'/page.test.tsx` for focused UI/route tests. No new migration or dependency is needed.

## Function Explorer Phase 6A

The backend model is derived from the persisted static graph, so no migration or new dependency is required. New trusted compiler-AST graph generations include bounded syntax facts; existing graphs still load with `partial` analysis. Run `npx vitest run packages/core/src/function-explorer.test.ts packages/scanners/src/static-protocol-graph.test.ts` for backend coverage, then the standard typecheck/test/lint/build gates. The API requires a scan with a finalized static graph and an exact contract/function node ID. The visual route is documented above.


## Contract Explorer local check

Configure the normal local `.env`, run `npm run dev`, and open an existing completed hunt at `/hunts/<scan-id>`. Choose **Open Protocol Map**, select a contract node, then **Open Contract Explorer**. Check the classification and immutable source link, entry points and function filters, callers/callees, unresolved relationships, exact finding links and **Show in Protocol Map**. Historical scans have no fabricated graph; create a new authorised scan if needed. The deterministic unit fixture is `npx vitest run apps/web/lib/contract-explorer.test.tsx`. No AI call, live RPC or blockchain transaction is needed.

## Protocol Map local check

Start with `npm run dev` after configuring the normal local `.env`, then open an existing completed hunt at `/hunts/<scan-id>`. Use **Open Protocol Map**. If no graph exists, create a new authorised scan; historical scans are intentionally not backfilled. The deterministic graph adapter fixture can be checked without an external repository using `npx vitest run apps/web/lib/protocol-map.test.ts`. On the map, verify zoom/pan, search, filters, presets, a node and edge detail, exact source link, finding link and an unresolved-target notice. The source page uses only immutable scan snapshots; a scan without one shows an unavailable state. No live RPC, AI call or blockchain transaction is needed.

## Protocol Intelligence Phase 2

New scans attempt a deterministic Repository Map after scanner source alignment. Inspect the finalized result with `GET /api/scans/:id/repository-map`; historical or unsupported scans return 404 without a fabricated map. The map is navigation metadata. It does not execute repository scripts, call AI, change verification authority or compute audit-priority scores. The mapper's source-root, symlink, malformed-file and large-tree tests run in the normal `npm test` suite.

## Impact Lab D1 validation

The opt-in B1/C1 local Anvil/Forge test below now exercises D1 trace capture through Anvil 1.7.1 `callTracer`: root call, nested CALL, DELEGATECALL, local receipt, failed trace capture, zero upstream debug/transaction methods, state diff and baseline reset. A fixture-only local reverted transaction checks Anvil's revert shape; Forge's fixed script mode does not submit its simulated reverting call. Unit tests cover parser bounds, canonical hashing, provenance tampering, missing nodes and migration behavior. The production Compose PoC worker rebuild/smoke remains a v0.3 release gate; do not download remote Foundry or compiler inputs for D1.

## Impact Lab C1 validation

The optional B1 real integration command below now also tests C1 PRE/POST capture on fixture Anvil A → proxy → fork B. The benign script sends one wei and writes storage slot zero on B; the test checks exact native/storage changes, upstream immutability, zero upstream transaction submissions, durable hashes after B resets, PRE and POST failure cleanup, and compile-failure PRE-only semantics. Unit and migration tests run in `npm test`. No external provider, compiler download or real-chain transaction is required. A production Compose worker image build should use existing trusted build inputs; do not fetch a compiler or Foundry artifact to satisfy this smoke.

The cached worker image ID used by the opt-in C1 test is newer than the local `contracthunter-impact-poc-worker:b1` tag. That older tag failed the real loopback bridge smoke. Rebuild the Compose worker from current trusted sources and repeat the live smoke before release; a full Compose build was not attempted in the offline C1 validation because its Dockerfile contains remote Foundry `ADD` inputs.

## Impact Lab B1 local integration

The optional B1 test requires a checksum-approved Anvil, a trusted locally built worker image ID, and an existing cached solc 0.8.36 compiler volume. It never downloads a compiler or uses a third-party provider. Run `CONTRACTHUNTER_LOOPBACK_TEST=1 IMPACT_TEST_ANVIL=/path/to/approved/anvil IMPACT_B1_WORKER_IMAGE=sha256:<image-id> IMPACT_B1_TEST_COMPILER_VOLUME=<local-volume> npx vitest run apps/web/lib/impact-poc-real.test.ts`. It starts local upstream Anvil A, the ContractHunter read-only proxy, fork B and a Docker `network none` worker; the benign reviewed script transfers one wei only on B, verifies upstream unchanged, resets B and checks FFI denial. The normal Compose worker is built from the digest-pinned Foundry 1.7.1 stage and receives only the shared control socket and read-only compiler cache subpath. Web and worker never mount the Docker socket. No PoC runs during `npm test` unless the opt-in environment is set.

Prerequisites are Node.js 20+, npm, Docker, and Docker Compose. The web service uses UID/GID 10001:10001. The separate verification worker uses UID/GID 10002:10001. Docker's default enforcing seccomp and AppArmor profiles are used; there is no custom host profile to install.

## Impact Lab A3 local integration

The pinned Foundry v1.7.1 Docker build stage now installs both Forge and Anvil; the runner image receives Anvil, while the verification-worker image still receives Forge only. The host integration accepts an Anvil binary only when `IMPACT_TEST_ANVIL` points to a regular, non-group/world-writable file with the exact checksum of the pinned amd64 artifact. It never downloads a binary. The test first creates a disposable local Anvil upstream fixture, then launches a second Anvil through ContractHunter's read-only proxy. It exercises exact identity, state reads, fork-only transfer, snapshot and revert, and method recording. Run it explicitly with `CONTRACTHUNTER_LOOPBACK_TEST=1 IMPACT_TEST_ANVIL=/path/to/approved/anvil npx vitest run packages/scanners/src/impact-real-anvil.test.ts` on a Linux amd64 host with loopback binding allowed. The test skips otherwise; it does not use `IMPACT_RPC_CONFIGS` or a third-party endpoint.

Build the fixed probe image with `docker build --network none -t contracthunter-impact-probe:local docker/impact-probe`, inspect its immutable `sha256:` image ID, and set `IMPACT_PROBE_IMAGE_ID` to that ID for the same integration command to run the live Docker isolation probe. This requires a trusted local Docker controller and daemon permission; the standard Compose web container does not get a Docker socket. The probe uses one per-session Unix socket, Docker network mode `none`, and no host filesystem/data mount. Test-only Docker `exec` performs harmless TCP and cross-session socket probes. The ordinary `npm test` skips opt-in loopback/Docker integration tests when their prerequisites are absent. The dedicated runtime unit tests can be run with `CONTRACTHUNTER_LOOPBACK_TEST=1 npx vitest run packages/scanners/src/impact-poc-runtime.test.ts` where Unix-socket listening is allowed. No solc or live RPC is needed.

```bash
cp .env.example .env
npm install
npm run dev
npm run typecheck
npm test
npm run lint
npm run build
docker compose config
docker compose build
docker compose up -d
docker compose ps
```

Local development without the Compose worker can scan and plan; “Verify locally” fails closed with `verification_worker_unavailable`. Production verification requires the worker's isolated container, the dedicated workspace and IPC named volumes, and a compiler already prepared in `contracthunter-data/tool-home`. Compose mounts only that subpath into the worker as read-only. If the Docker engine cannot mount named-volume subpaths, do not replace it with a whole `/data` mount.

The `contracthunter-data` volume holds the database, repository clones, and trusted compiler cache. Keep it when rebuilding or restarting. On a fresh install, the one-shot `contracthunter-data-init` service prepares `/data/tool-home` as UID/GID `10001:10001` before the worker starts. Compose may create the worker container first and leave an empty root-owned subpath; the initializer safely replaces only that empty, unwritable directory. A populated cache is never replaced. No manual directory creation, ownership change, compiler install, or host AppArmor setup is needed to start the stack. The worker can start with an empty compiler cache; later scans prepare trusted compilers through the web service.

The `verification-workspaces` volume stores generated harness workspaces, while `verification-ipc` stores only the worker socket. Neither contains the main database. Old verification history and plans remain in SQLite and are reusable; generating another AI plan is unnecessary for a rerun.

Schema upgrades are explicit and transactional. `schema_migrations` records migrations `0001` through `0015`; v0.2.2 ends at `0008`, Impact Lab A1/A2 add `0009`/`0010`, B1 adds `0011`, C1 adds state artifacts in `0012_v0_3_impact_state_capture`, D1 adds immutable local trace artifacts in `0013_v0_3_impact_local_traces`, Protocol Intelligence Phase 2 adds immutable repository maps in `0014_protocol_repository_maps`, and Phase 3 adds immutable static graphs in `0015_protocol_static_graphs`. Startup applies all pending migrations and SQLite quick-integrity, foreign-key, required-table, and engine/proposal validation before committing one outer transaction. Historical rows receive no fabricated snapshot, compilation, fingerprint, reuse, state, trace, repository-map or static-graph provenance. Migration does not rewrite scan, hypothesis, verification, invariant evidence, or lifecycle history. A migration/index conflict or validation failure aborts startup and rolls back every pending schema change. Release testing must use an SQLite backup/copy, never the user's live database.

Every invariant retry uses a new run ID and workspace. Every replay retry regenerates source closure, harness, configuration and manifest from the persisted plan/replay identity into a new replay-run workspace; the normalized artifact fingerprint, harness hash, replay-plan hash and counterexample hash must still match before execution. Existing proposal, run, artifact and replay-attempt history is never overwritten.

Workspace cleanup is operator-invoked and dry-run by default:

```bash
npm run workspace:retention -- --root /path/to/verifications --database /path/to/contracthunter.db
npm run workspace:retention -- --root /path/to/verifications --database /path/to/contracthunter.db --apply
```

The default policy keeps completed workspaces for 7 days and failed/refused workspaces for 14 days; both windows are configurable from 1–3650 days. It considers only immediate UUID directories with matching immutable database history and a recognized structured-verification, Foundry invariant, Echidna invariant, or replay manifest. Queued/running workspaces, replay artifacts with an active replay, unknown workspace kinds, symlinked trees, and records without a terminal timestamp are always kept. `--apply` rechecks eligibility before removing a directory. Database evidence/history and canonical hashes are never removed. There is no automatic cleanup on startup.

Use `docker compose exec -T verification-worker` to inspect `id`, `/proc/self/status`, `/proc/self/attr/current`, `/proc/net/route`, `/proc/net/ipv6_route`, `/sys/class/net`, and `/sys/fs/cgroup/pids.max`. The worker should have only `lo`, no usable default route, zero effective/bounding capabilities, `NoNewPrivs: 1`, `Seccomp: 2`, enforcing AppArmor, and a PID limit of 64. The socket should be mode 0660. The worker should not see `/data/contracthunter.db`, `/data/repositories`, `/var/run/docker.sock`, OpenAI/GitHub secrets, or proxy keys.

A Docker run is also the release smoke test for production-only Next.js behavior. Check `/`, an existing hunt page, an existing hypothesis page, and a saved-plan verification where practical. `.env` must not be committed.

The standard typecheck, test, lint, build, migration, and fresh Compose gates do not require a cached solc. When a trusted cached compiler already exists, release validation may additionally run a narrow real `plain-solidity-exact-pragma-v1` compilation and worker smoke. If it does not, record the limitation and run the deterministic compiler-boundary tests; do not download or install solc solely for release validation. Use a separate Compose project and fresh volumes for install probes so the normal data volume remains untouched.

## Impact Lab Phase A1 development

The A1 engine is an internal service and test harness; it has no public API, CLI, or GUI. Run `npx vitest run packages/scanners/src/impact-fork.test.ts packages/db/src/impact-fork-sessions.test.ts packages/db/src/migrations.test.ts` for the fork boundary and additive migration. The ordinary test suite uses deterministic mocks and needs no Anvil or live RPC. A real lifecycle smoke is optional only when an approved local Anvil binary already exists at `/usr/local/bin/anvil` or `~/.foundry/bin/anvil` and Linux `setpriv` is available. Do not download Anvil or use a production RPC for routine tests. Provide an upstream URL only through a runtime `IMPACT_RPC_*` environment reference; the URL and credentials are never persisted or passed to Anvil. The default Compose image does not provision Anvil in A1.

## Impact Lab Phase A2 development

Set `IMPACT_RPC_CONFIGS` to a JSON array of `{id, chainId, network, upstreamUrlSecretRef, enabled}`; each secret reference must name an `IMPACT_RPC_*` environment variable containing an HTTPS provider URL. Use an exact block and deployed target address. The existing approved local Anvil binary and Linux `setpriv` are required for real forks. Run `npx vitest run packages/scanners/src/impact-fork.test.ts packages/scanners/src/impact-fake-provider.test.ts apps/web/lib/impact-lab.test.ts packages/db/src/impact-fork-sessions.test.ts packages/db/src/migrations.test.ts` for deterministic A2 checks. Tests do not download Anvil, use live RPC, send transactions or call OpenAI. The opt-in loopback proxy socket test passed with a mocked provider. No Anvil binary or test RPC was configured during A2 validation, so real-fork smoke remains unverified.
