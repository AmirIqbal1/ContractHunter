# ContractHunter AI Handoff

> Read this file before making significant changes to ContractHunter.

## Project purpose

ContractHunter is a locally hosted smart-contract security analysis workstation for authorised analysis only. Repositories and their contents are hostile input. It combines deterministic static scanners, optional manually triggered AI reasoning, ranked hypotheses, and explicit local verification.

## Current version state

Latest released: `v0.1.9`.

`v0.2.0` is in development. Milestone 1 implements internal executable-invariant plans and deterministic harness foundations. Milestone 2 adds networkless worker execution, deterministic bounded Forge result interpretation, dynamic evidence and separate immutable run history. These are not v0.1.9 released capabilities.

## Current stack

TypeScript monorepo; Next.js in `apps/web`; SQLite/Drizzle in `packages/db`; domain, configuration, and safety schemas in `packages/core`; Slither, Aderyn, compiler management, and verification in `packages/scanners`; Docker-first deployment; optional OpenAI integration.

## Current workflow

```text
Static: clone → detect → dependencies → compiler → Slither/Aderyn → correlate → completed
AI: manual protocol analysis → manual specialist security review → hypotheses
Verification: Generate Verification Plan → review → Validate plan → Verify locally
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

The web image runs as UID/GID `10001:10001` and retains normal networking for scanning and optional AI. Web validates plans and persisted identity, builds and checks deterministic workspaces, interprets execution facts, creates dynamic evidence, and controls hypothesis status. A one-shot, networkless, non-root `contracthunter-data-init` service ensures `/data/tool-home` is usable on fresh volumes before the worker starts. Compose may pre-create an empty root-owned subpath; the initializer replaces only that empty directory and does not alter an existing cache. The dedicated verification worker runs as UID/GID `10002:10001` with `network_mode: none`, `pids_limit: 64`, no capabilities, no new privileges, a read-only root filesystem, and Docker's default seccomp and enforcing AppArmor profile. Its startup and per-job preflight inspect actual kernel state, interfaces, routes, environment keys, and forbidden filesystem paths. Web sends only strict, bounded identifiers over a group-restricted Unix socket; no Solidity source or commands cross it. Worker sees the bounded workspace volume and read-only `tool-home` subpath, but no database, general repository store, API credentials, or Docker socket. It rechecks the workspace and compiler before fixed offline Forge execution under `prlimit`, with FFI disabled. It returns facts only; web has no verification Forge fallback. Nested Bubblewrap and custom Docker security profiles are historical development work, not the production path.

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

`ExecutableInvariantService` is an internal entry point. It binds plans to persisted scan/hypothesis state, creates immutable `executable_invariant_runs` rows, invokes the worker, interprets pinned Forge JSON into bounded property evidence, and never changes hypothesis status. Successful fuzz/invariant runs mean no counterexample was found within the configured run/depth budget; they are not formal proof. Counterexamples are contradictory evidence for the claimed property. No AI proposals, public endpoint or UI were added. Tested the three synthetic fixtures and a legacy BrokenAccessControl verification through an isolated Compose worker using trusted solc 0.8.36. The legacy fixture's exact `0.8.24` pragma was widened only in the isolated probe copy because no trusted 0.8.24 compiler was cached.
