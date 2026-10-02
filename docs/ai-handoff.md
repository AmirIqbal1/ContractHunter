# ContractHunter AI Handoff

> Read this file before making significant changes to ContractHunter.

## Project purpose

ContractHunter is a locally hosted smart-contract security analysis workstation for authorised analysis only. Repositories and their contents are hostile input. It combines deterministic static scanners, optional manually triggered AI reasoning, ranked hypotheses, and explicit local verification.

## Current version state

Current released version: `v0.2.1`. Current development target: `v0.2.2` (Milestone 1 Parts 1, 2A and 2B-1 implemented, not released). Git commit/tag/push and publication remain manual operations outside AI/Codex.

v0.2.0 includes executable invariant plan v1, bounded fuzz/stateful worker execution, manual AI semantic proposals, deterministic counterexample replay, explicit relevance review, authoritative invariant evidence, centralized lifecycle transitions, transactional v0.1.9 migration, retry workspaces and release regression probes.

v0.2.1 provides a guarded, manually selected Echidna stateful invariant engine beside Foundry. The patched Echidna 2.3.3 build, source archive, compatibility patch, lock information, and checksums live under `third_party/echidna`; the Docker build uses a digest-pinned Nix stage and hash-checks the reproducible static ELF. Public actions persist authoritative engine identity; migration maps historical v0.2.0 invariant runs to Foundry without rewriting evidence. Exact Echidna counterexamples reuse the canonical Foundry replay path. Replay must reproduce, then pass explicit relevance review before authoritative supporting evidence is recorded and centralized lifecycle authority evaluates a transition. No automatic dual execution, AI engine choice, or fallback is permitted. Echidna semantics remain narrower than Foundry's.

## Current stack

TypeScript monorepo; Next.js in `apps/web`; SQLite/Drizzle in `packages/db`; domain, configuration, and safety schemas in `packages/core`; Slither, Aderyn, compiler management, and verification in `packages/scanners`; Docker-first deployment; optional OpenAI integration.

## Current workflow

```text
Static: clone → detect → dependencies → compiler → Slither/Aderyn → correlate → completed
AI: manual protocol analysis → manual specialist security review → hypotheses
Verification: Generate Verification Plan → review → Validate plan → Verify locally
Invariant: Generate semantic proposal → review → validate → bounded run → counterexample replay → relevance review → lifecycle authority
```

Static scanning always completes before optional AI stages. AI stages are manual and optional.

## Hypothesis trust rules

Statuses are `candidate`, `investigating`, `likely-valid`, `verified`, and `rejected`. AI hypotheses begin as `candidate`; confidence is capped at 85 before verification. UI/API code must not directly set `verified`. Only authoritative completed supporting dynamic evidence may perform that transition.

## Current benchmark

The benchmark repository is `AmirIqbal1/contracthunter-vulnerable-lab`. Its planted families are ReentrancyVault, BrokenAccessControl, TxOriginWallet, UncheckedExternalCall, TimestampLottery, and safe control SafeVault. The latest observed benchmark had 42 raw findings, 37 Investigations, and 5 multi-scanner Investigations; all five planted issue families surfaced statically. AI represented four of five exact root causes clearly, while UncheckedExternalCall hypotheses overemphasised broader arbitrary-call capability. Root-cause deduplication remains an improvement target.

## v0.1.9 verification

`VerificationHarnessPlan` supports actors, symbolic actor/instance address arguments, decimal uint256 and bool arguments, caller identity, deploy/call/read-uint/read-address/read-balance/fund operations, and uint/address equality or inequality assertions. Limits are eight actors, eight call arguments, and 100 ETH funding. Literal AI-supplied addresses, raw calldata, arbitrary expressions, cheatcode names, and arbitrary Solidity are rejected. ContractHunter chooses deterministic `vm.prank` and `vm.deal` semantics internally. AI proposes verification semantics; ContractHunter supplies authoritative scan, hypothesis, commit, and compiler identity. A single trusted compiler is injected automatically; multiple trusted compilers fail closed until a deterministic source-to-compiler mapping exists. Historical narrow plans remain valid.

The BrokenAccessControl proof can represent attacker → `setOwner(attacker)` → `owner() == attacker` → optional funding → attacker withdrawal → target balance zero, subject to fail-closed execution requirements.

## Current execution boundary

The original Docker fixture failure exposed a cache-binding bug: scanning prepared solc-select artifacts below `.solc-select`, while verification mounted an unrelated `.svm` cache. v0.1.9 validates the exact cached artifact/version from the read-only `tool-home` volume subpath and runs offline Forge with compiler autodetection disabled. Missing compilers fail as `trusted_compiler_unavailable` without installation.

The web image runs as UID/GID `10001:10001` and retains normal networking for scanning and optional AI. Web validates plans and persisted identity, builds and checks deterministic workspaces, interprets execution facts, creates dynamic evidence, and controls hypothesis status. A one-shot, networkless, non-root `contracthunter-data-init` service ensures `/data/tool-home` is usable on fresh volumes before the worker starts. Compose may pre-create an empty root-owned subpath; the initializer replaces only that empty directory and does not alter an existing cache. The dedicated verification worker runs as UID/GID `10002:10001` with `network_mode: none`, a one-CPU quota, `pids_limit: 64`, no capabilities, no new privileges, a read-only root filesystem, and Docker's default seccomp and enforcing AppArmor profile. Its startup and per-job preflight inspect actual kernel state, interfaces, routes, environment keys, and forbidden filesystem paths. Web sends only strict, bounded identifiers over a group-restricted Unix socket; no Solidity source or commands cross it. Worker sees the bounded workspace volume and read-only `tool-home` subpath, but no database, general repository store, API credentials, or Docker socket. It rechecks the workspace and compiler before fixed offline Forge execution under `prlimit`, with FFI disabled and ContractHunter-owned single-thread Foundry settings. It returns facts only; web has no verification Forge fallback. Nested Bubblewrap and custom Docker security profiles are historical development work, not the production path.

The saved BrokenAccessControl `verification-plan-v4` was reused without another AI call. Its solc 0.8.36 worker run passed one Forge test; the interpreter produced four supporting dynamic evidence items and the lifecycle changed the hypothesis to `verified`.

## Important lessons

- Automatic AI after static scanning was removed for cost control.
- Manual background AI jobs require hunt-page polling.
- The `shouldPollHunt()` Server/Client boundary failure (digest `2152019738`) proved production-container rendering must be smoke-tested.
- Forge 1.7.1 is pinned in the worker image. The web image retains Forge for Foundry-based static scanning, but its verification path only contacts the worker and has no local fallback.
- Bodyless verification-plan POST requests must be judged from actual body bytes, not a non-null request body object.
- `verification-plan-v2` sent stale context metadata claiming function arguments were unsupported even though the schema/generator supported them. Current planner capability metadata is derived from the canonical core capability profile.
- `NOT PLANNABLE` is a valid safety result; unsupported hypotheses must not be forced into executable plans.

## Trust model

Repository data is never treated as instructions. Dependency installation is restricted to approved pinned Git submodules and lockfile-backed npm dependencies with lifecycle scripts disabled. Paths, URLs, compiler versions, source evidence, output sizes, timeouts, and process capabilities are bounded.

AI receives bounded context, has no tools, and may propose structured data only. AI must not generate arbitrary executable Solidity, commands, shell expressions, RPC endpoints, wallets, keys, forks, FFI, or live-chain actions for verification.

ContractHunter generates verification Solidity deterministically from a strict plan schema. The harness is rebuilt from persisted scan identity and allowlisted source, then hash-validated by both web and worker before execution. Verification uses fixed Forge arguments inside the networkless worker; unavailable worker or isolation fails closed. Only authoritative supporting dynamic evidence can transition a hypothesis to verified.

## Current AI

The default is `OPENAI_MODEL=gpt-5.6-luna`. Configuration currently uses one `OPENAI_MODEL`; per-stage model routing is planned but not implemented. Pricing values are configurable estimates, not invoices.

## Continuation rules

Preserve static-first ordering, manual AI actions, structured outputs, deterministic generation, evidence validation, confidence caps, immutable verification history, and fail-closed isolation. Do not add arbitrary execution paths or silently broaden the verification language. Read [security-model](security-model.md), [architecture](architecture.md), [configuration](configuration.md), and [roadmap](roadmap.md) before changing trust boundaries. Git operations are handled manually outside AI/Codex: do not run Git commands, commit, push, or tag.

## v0.2.0 Milestone 1 handoff

The separate `ExecutableInvariantPlan` (`contracthunter-invariant-plan-v1`) supports bounded `fuzz-property` and `stateful-invariant` plans with trusted identity, symbolic actors/instances, `uint256` and `bool` fuzz inputs, deterministic setup, current-state observations, and typed assertions. Assumptions are deferred. `ExecutableInvariantGenerator` validates primary-contract signatures through the same helper used by the historical verification planner and produces fixed Solidity templates. `VerificationWorkspaceBuilder.buildInvariant` creates a bounded source closure and an invariant-specific hashed manifest and Foundry configuration. SHA-256 of canonical plan JSON supplies the Foundry `[fuzz].seed`; Foundry 1.7.1 also uses it in the invariant runner. Fuzz runs are 128; invariant runs/depth are 64/32 with `fail_on_revert = false`. No forge-std dependency is downloaded; the generated stateful test has a minimal ContractHunter target registration helper.

Milestone 1 changed no AI schemas/prompts, public API, UI, worker IPC, hypothesis lifecycle or production database behavior. Preserve v0.1.9 verification output and worker isolation.

## v0.2.0 Milestone 2 handoff

The worker protocol adds a strict `execute-invariant` branch; the caller supplies only bounded run/workspace identity, scan/hypothesis/commit/compiler identity, plan hash, mode and fixed limits. Version 2 invariant manifests embed the structured plan for independent worker revalidation. The worker checks workspace path, symlinks, exact expected files, source hashes, generated harness/config, manifest and compiler identity before fixed `forge test --json` via the existing trusted compiler resolver and `prlimit`. The version 1 verification branch remains separate. Forge 1.7.1 cannot combine `--json` with `--color never`; `NO_COLOR=1` is set in the fixed environment.

`ExecutableInvariantService` binds plans to persisted scan/hypothesis state, creates immutable `executable_invariant_runs` rows, invokes the worker, interprets pinned Forge JSON into bounded property evidence, and never changes hypothesis status. Successful fuzz/invariant runs mean no counterexample was found within the configured run/depth budget; they are not formal proof. Counterexamples contradict the tested property but remain `unreviewed` relative to the hypothesis. Milestone 3 adds the public manual endpoint/UI workflow. The three synthetic fixtures and a legacy BrokenAccessControl verification are exercised through an isolated Compose worker using trusted solc 0.8.36; the legacy fixture's exact `0.8.24` pragma is widened only in the isolated probe copy because that probe cache contains 0.8.36.

## v0.2.0 Milestone 3 handoff

The hypothesis page now has a separate Executable invariant testing section. `invariant-plan-v1` asks the configured provider for one tool-free semantic proposal under the canonical invariant capability profile. The proposal schema has no authoritative IDs, compiler, source paths, commands or Solidity. `InvariantProposalService` selects bounded validated source context, injects persisted scan/hypothesis/commit and a unique compatible trusted compiler, validates the generated harness, and appends an immutable proposal-history row. It stores source hashes so validation refuses a source change after review. Failure categories are bounded; raw source and provider payload are not logged or persisted.

Generation is one manual POST and never executes. Validation is a separate bodyless POST. Execution is another bodyless POST referencing the persisted proposal ID, revalidates it, and uses the Milestone 2 networkless worker service. The UI shows plan semantics, mode, compiler, configured bounds, plan hash, and bounded result evidence. Neither a proposal nor a fuzz/invariant run transitions hypothesis status. Automated tests use provider mocks; no real OpenAI request was made. Browser testing with actual credentials must be started manually by the user.

## v0.2.0 Milestone 4 handoff

Invariant evidence uses separate `propertyOutcome` and `hypothesisRelation` fields. The proposal's only relationship is `hypothesis-predicts-property-violation`; a counterexample therefore begins as an unreviewed property violation, while held-within-bounds stays neutral to the vulnerability hypothesis. The UI shows this relationship before execution.

A replayable result stores a pinned Forge parser version and canonical typed counterexample. The server can generate a deterministic artifact without executing it. The artifact maps persisted values/action IDs to the original plan, generates a fixed positive violation assertion, and records replay/counterexample/harness/workspace hashes. A separate manual action sends the strict replay request to the existing worker. Only `reproduced` permits the manual **Confirm relevance** action. That action appends review and authoritative evidence records, then invokes the shared lifecycle authority; handlers never set verified directly. No replay or review path uses AI.

## v0.2.0 release-hardening handoff

`schema_migrations` makes the v0.1.9 → v0.2.0 upgrade explicit, additive and transactional. Startup performs quick-integrity, foreign-key and required-table validation and fails before application access if migration cannot commit cleanly. Migration does not rewrite hypothesis or verification statuses, and historical failed attempts remain intact. The upgrade regression uses a copied v0.1.9-shaped database and then appends new proposal/run/replay history.

Invariant runs already used fresh run-ID workspaces. Replay execution now does the same: each attempt creates a replay-run row, regenerates deterministic files from persisted replay/invariant data, normalizes the new workspace fingerprint against the immutable artifact ID, revalidates source/harness/config/hashes, and only then contacts the worker. Mutated artifact build/cache output is never authoritative input. The operator-only workspace-retention command is dry-run by default, never touches active or unknown workspaces, keeps recent failures longer, and never deletes database history.

Forge 1.7.1 output is accepted only for the exact expected suite/tests, assertion failure marker, typed bounded counterexample and exit-code relationship. Missing/duplicate/additional tests, malformed/truncated/oversized JSON, invalid uint/bool/action data, missing counterexamples, output truncation and pass/fail exit inconsistencies fail closed.

`propertyOutcome` describes only the generated property (`held-within-bounds` or `counterexample-found`). `hypothesisRelation` is separate (`neutral`, `unreviewed`, then `supports` only after reproduction and explicit review). Bounded fuzzing is not formal proof; held-within-bounds does not mean safe, secure, proven, verified, or vulnerability-disproved.

The worker boundary remains: `network_mode: none`, read-only root, UID/GID `10002:10001`, zero effective/bounding capabilities, `no-new-privileges`, `pids_limit: 64`, one CPU, `FOUNDRY_THREADS=1`, default enforcing seccomp/AppArmor, no Docker socket/database/general repository/API secrets/proxy keys, and read-only trusted compiler cache. Process count is enforced by the checked container cgroup; per-UID `RLIMIT_NPROC` was removed because it is host-global and caused separate Compose projects using UID 10002 to interfere. CPU, address space, file descriptors and file size remain under `prlimit`, with controller wall/output bounds.

Release probes cover vulnerable accounting → reproduced, stateful access control → reproduced, safe accounting → held-within-bounds/no replay, deliberate non-reproduction → no evidence, reviewed reproduction → authoritative evidence/centralized verified transition, plus the independent v0.1.9 structured-verification branch. Production advisory review pinned Next.js 16.3.3 and sharp 0.35.4; `npm audit --omit=dev` was clean. No real OpenAI request is part of automated validation.

## v0.2.1 Milestone 1 Echidna handoff

Stock Echidna 2.3.3 JSON could not identify properties or terminal outcomes reliably. A four-file compatibility patch against official tag `v2.3.3` (commit `4454f3a337ed58e89a3be488b8eac03e83cd40f2`) emits one pure, versioned JSON document with exact typed property names, explicit bounded terminal outcomes, seed, stop reason, and transactions. Two clean serial Nix builds produced the same static ELF SHA-256 `b6f84d8d48fcffe4d48b9be0378e65f37a36c304c3325d72aa868fcfac204ff1`; the exact Docker stage checks this hash. `libsecp256k1` is linked statically. `crytic-compile==0.3.11` and its Python wheels are hash locked in the separate digest-pinned Python stage.

`EchidnaInvariantGenerator` and its compatibility validator accept a narrow stateful subset: one deployment, no actors/callers/setup calls/funding, generated uint256/bool actions, uint/balance observations and uint equality checks, and no caller or environment sensitive source. Unsupported plans return explicit bounded reasons. The generated harness exposes uniquely named `echidna_ch_*` properties. The first 48 bits of the canonical plan hash form the numeric seed. A strict version 3 manifest and regenerated source/config bytes bind execution. The worker has a separate bounded `execute-echidna-invariant` operation, tool preflight, fixed argv, exact trusted solc selection, and compatibility JSON parser. Exact ordered action transactions can feed the existing canonical replay plan and Foundry replay worker; unrepresentable failures retain their property outcome with replay unavailable. Foundry's version 2 manifests and execution path remain valid.

Milestone 1 is an internal engine path. No AI prompts, public engine selector, automatic dual execution, persistence migration, or hypothesis lifecycle policy change was added. Future UI/persistence work must preserve the existing deterministic replay → reproduced → explicit relevance confirmation → centralized lifecycle authority route.

## v0.2.1 Milestone 2 handoff

Public invariant validation reports Foundry compatibility and bounded Echidna compatibility reasons from the existing validator. Users explicitly run one engine through bodyless Foundry or Echidna routes; the legacy run route remains a Foundry alias. Additive transactional migrations add authoritative `engine`, bounded engine audit metadata, and a nullable proposal binding to invariant runs and `source_engine` to replay artifacts, defaulting historical rows to Foundry. Echidna's web service revalidates the persisted proposal, source, compiler, and compatibility before its deterministic workspace and worker operation. Both engines persist normalized property evidence; exact Echidna action sequences reuse Foundry deterministic replay, explicit relevance review, and centralized lifecycle authority. Non-mappable counterexamples remain persisted with replay unavailable. The compatible Echidna subset has not expanded, and AI prompts, engine selection, and lifecycle rules have not changed.

## v0.2.1 Milestone 3 Part 1 hardening handoff

Part 1 hardening is complete. The pre-edit baseline was 428 tests across 52 files; the final suite was 436 passing tests across 54 files, with typecheck, lint, build, Compose config/build/up, and production health/SSR smoke checks passing. Copied v0.2.0-shaped history was compared across every historical table before and after upgrade, including failed attempts, reviews, evidence, and verified status. Startup now wraps all pending migrations and integrity/foreign-key validation in one transaction, so a later migration or validation failure leaves the copy unchanged. Failure probes cover malformed/missing legacy schema, duplicate migration-record inconsistency, migration statement conflicts, and foreign-key violations.

Separate fresh Compose volumes started data-init, healthy web, and the worker with no compiler. Both engine jobs refused the absent 0.8.36 solc as `trusted_compiler_unavailable` without a worker download. After the isolated web-side trusted cache was prepared, real worker probes produced safe Foundry/Echidna `held-within-bounds`, vulnerable Echidna and Foundry `counterexample-found`, Echidna-origin replay `reproduced`, a Foundry-origin replay and retry both `reproduced`, and deliberate replay `not-reproduced` with no evidence. Explicit relevance review was required before authoritative evidence and the centralized verified transition. A Foundry 1.7.1 stateful counterexample exposed formatted `args` text with scientific notation; the parser now uses `raw_args` when present, with a regression fixture. Historical Foundry fuzz and caller-sensitive stateful paths passed.

Echidna malformed action names and invalid uint/bool values now reject the entire result; valid terminal failures with noncanonical sender, destination, value, or delay remain nonreplayable observations. Public history refuses mismatched persisted engine/evidence/plan identity, and replay execution rechecks source engine, run, proposal, compiler, commit, and counterexample binding. Historical proposal association is shown only when its plan hash has one matching proposal. Retry tests verify fresh Foundry, Echidna, and replay workspaces. The dry-run retention helper now recognizes Echidna manifests and conservatively keeps unknown or symlinked trees. Build-support checks bind source, patch, lock, license, recipe, Docker pins, and runtime constants. No real OpenAI request was made.

## v0.2.1 final release preparation

The application packages, lockfile workspace metadata, health response, and UI version label use `0.2.1`. The final security fix pins Next.js 16.3.8, resolving GHSA-vcvr-r3jv-pc5j; `npm audit --omit=dev` reported zero vulnerabilities. Typecheck, lint, build, and all 436 tests across 54 files passed at release preparation. The final Docker images built; a separate Compose project with fresh volumes completed data-init, started a healthy v0.2.1 web service and a worker that passed Echidna preflight with an initially empty compiler cache. After isolated trusted compiler preparation, safe Foundry and Echidna runs held within bounds, vulnerable Echidna found a counterexample, its replay reproduced, and the independent structured verification path completed. Live worker inspection confirmed its networkless, read-only, non-root, capability-free boundary. v0.2.1 is now the released baseline. Keep the above narrow stateful Echidna compatibility boundary; no caller/actor/setup/funding or fuzz-property translation has been added. `held-within-bounds` is bounded evidence, not formal proof, and a counterexample requires exact replay plus explicit relevance review before it can create authoritative evidence. v0.2.2 targets smarter verification/plan selection and root-cause grouping; v0.3 targets more autonomous local audit/reporting.

## v0.2.2 Milestone 1 Part 1 handoff

An additive, read-only strategy assessor now represents structured verification, Foundry fuzz property, Foundry stateful invariant, and Echidna stateful invariant separately from engines and plan modes. It extracts bounded requirements only from exact Slither/Aderyn rule IDs in correlated findings, after checking hypothesis investigation links, scan identity, and the primary contract/path. It never infers from AI hypothesis prose, scanner descriptions, or repository content. Missing/unmapped evidence yields `unknown`; known unsupported requirements yield `incompatible`. Reasons are stable codes suitable for a later public mapper. The database adapter only reads historical rows. No migrations, prompts, planner, execution route, UI, replay, evidence, or lifecycle behavior changed.

For the current exact-rule fixtures, `protected-vars` requires explicit caller semantics (structured and Foundry profiles can represent it; Echidna cannot); `reentrancy-eth`, `tx-origin`, `unchecked-lowlevel`, and `timestamp` expose requirements that current plans cannot express. These are advisory capability judgments, not concrete plan validation or proof that a named benchmark has a specific detector result. Safe controls or unknown rules remain `unknown`. Part 2B can connect strategy-aware planning only after preserving concrete plan validation, explicit execution, and the existing replay/relevance/lifecycle authority. Broader Echidna semantics and automatic execution remain outside this milestone.

## v0.2.2 Milestone 1 Part 2A handoff

The hypothesis page now renders a compact Verification options section from the same read-only persisted assessment as `GET /api/hypotheses/:id/verification-options`. A single server-side public mapper fixes order and converts closed reason codes to bounded display text; no raw scanner output or repository path crosses this new API. Unknown is visibly separate from incompatible. Compatible cards offer page-local strategy selection for planning preview only. Selection is not persisted or connected to either planner; no plan, AI request, worker run, evidence or lifecycle change follows from viewing or selecting. The existing structured verification and invariant proposal controls remain fully available, including when an option is unknown. Part 2B should bind an explicit strategy to generation with fresh concrete plan validation while preserving manual execution and the current replay/relevance/lifecycle authority.

## v0.2.2 Milestone 1 Part 2B-1 handoff

The new bodyless `POST /api/hypotheses/:id/verification-options/:strategy/generate` route accepts only a closed strategy path segment. It reloads persisted evidence and recomputes abstract compatibility before any provider call; each reused planner checks again. Structured selection reuses the historical structured planner and appends an immutable planning-attempt row. Foundry fuzz/stateful selections constrain the existing invariant proposal service to the server-derived mode. Echidna selection uses canonical stateful semantics and requires the existing concrete Echidna validator; failure is persisted as `strategy_concrete_plan_incompatible`, with no Foundry fallback or second provider request. Mode mismatch is `strategy_plan_mode_mismatch`. A known numeric division-order scanner rule contributes only a uint observation requirement to abstract assessment; actual ABI/source compatibility remains a separate concrete gate.

Migration `0004_v0_2_2_strategy_planning` adds nullable selected-strategy provenance to invariant proposal rows and a separate structured planning-attempt table without rewriting historical rows. Old manual generation routes still work and record no selected strategy. The Part 2A UI selection preview is not yet connected; Part 2B-2 can call this route and render the returned reviewable plan/proposal. No generation route runs Forge/Echidna, contacts the verification worker, creates dynamic evidence or invokes lifecycle authority. Keep explicit user validation and execution separate.

Git operations remain manual outside AI/Codex. Do not commit, push, tag, or publish from an AI session.
