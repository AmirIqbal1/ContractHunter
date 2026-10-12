# Development

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

Schema upgrades are explicit and transactional. `schema_migrations` records migrations `0001` through `0013`; v0.2.2 ends at `0008`, Impact Lab A1/A2 add `0009`/`0010`, B1 adds `0011`, C1 adds state artifacts in `0012_v0_3_impact_state_capture`, and D1 adds immutable local trace artifacts in `0013_v0_3_impact_local_traces`. Startup applies all pending migrations and SQLite quick-integrity, foreign-key, required-table, and engine/proposal validation before committing one outer transaction. Historical rows receive no fabricated snapshot, compilation, fingerprint, reuse, state or trace provenance. Migration does not rewrite scan, hypothesis, verification, invariant evidence, or lifecycle history. A migration/index conflict or validation failure aborts startup and rolls back every pending schema change. Release testing must use an SQLite backup/copy, never the user's live database.

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
