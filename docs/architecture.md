# Architecture

```text
apps/web          Next.js UI, API routes, scanning runner, verification planner/interpreter
packages/core     Domain models, Zod schemas, configuration, safety rules
packages/db       Drizzle schema and SQLite repository functions
packages/scanners Dependency/compiler managers, scanners, parsers, workspace builder, worker protocol
docker/verification-worker.ts  Networkless deterministic Forge controller
contracthunter-data-init       One-shot, networkless tool-home directory initialization
data volume       SQLite, cloned repositories, trusted compiler cache
verification-workspaces volume  Generated harnesses only
verification-ipc volume         Group-restricted Unix socket only
```

The application is a TypeScript monorepo. SQLite/Drizzle stores scans, findings, investigations, AI records, hypotheses, and verification history. Cloned repositories live below `REPOSITORY_DIR`; persistent data is below `DATA_DIR`. Docker provides the production runtime and persistent data volume.

```text
UI/API → runner → repository preparation → compiler resolution
                 → Slither → Aderyn → correlation → completed static scan
                 → optional AI analysis → optional specialist review
                 → hypotheses → optional plan → explicit local verification
```

The scanning runner is intentionally small and single-instance; interrupted jobs are marked failed after restart. Static scanning is completed before optional AI stages. A one-shot, non-root data initializer ensures the trusted-cache directory is usable before the worker starts, including when Compose pre-creates an empty root-owned subpath during container creation. For verification, the web service validates persisted evidence, copies an allowlisted source closure, generates a deterministic Foundry harness/configuration, validates hashes, and sends bounded identifiers to the worker over a Unix-domain socket. The worker revalidates the workspace and trusted compiler, then executes fixed Forge arguments under `prlimit` without networking. It returns execution facts only. The web interpreter creates dynamic evidence and applies the hypothesis lifecycle rules. There is no Docker socket, dynamic container creation, or nested Bubblewrap execution.

## v0.2.0 Milestone 1: executable invariant foundations

`ExecutableInvariantPlan` is a separate strict core schema from the historical `VerificationHarnessPlan`. It carries trusted scan, hypothesis, commit, and compiler identity and has `fuzz-property` and `stateful-invariant` modes. The new internal generator validates referenced functions and getters against the primary Solidity contract through the shared conservative source-signature validator. The existing verification planner also uses that validator, preserving its historical parsing behavior. The invariant workspace builder reuses the existing bounded, allowlisted source closure and writes ContractHunter-owned Solidity, `foundry.toml`, source hashes, a canonical plan hash, and a strict invariant manifest. The historical verification builder and manifest format are unchanged.

A fuzz property has one generated `testFuzz_<name>` call with `uint256` and `bool` inputs. A stateful test deploys a handler with named actions; each action maps to one validated function on a named instance. A small ContractHunter-owned target registration helper provides `targetContract` and `targetContracts()` in the shape Foundry uses for invariant discovery. No forge-std download or repository-controlled helper import is needed.

## v0.2.0 Milestone 2: worker execution and evidence

`buildInvariant` now writes a version 2 invariant manifest containing the bounded canonical plan. The worker validates the manifest against its own plan, regenerates the harness and Foundry configuration from source, hashes every source, and refuses symlinks and unexpected files before execution. The historical version 1 verification manifest and worker path remain supported separately. The strict Unix-socket request has an explicit `execute-invariant` command with identities, mode, plan hash and fixed limits; it accepts no executable, arguments or environment.

The worker reuses the trusted compiler resolver and executes `/usr/local/bin/forge test --json` inside the workspace via `prlimit`, offline and without FFI. Forge 1.7.1 rejects combining `--json` and `--color never`; `NO_COLOR=1` remains set in the worker-owned environment. The bounded JSON parser requires the exact generated test names, assertion failure marker, counterexample shape and exit-code relationship. Web maps each result to `held-within-bounds` or `counterexample-found` property evidence. A separate `executable_invariant_runs` table records immutable runs without updating hypothesis status; Milestone 3 exposes the reviewed manual endpoint/UI workflow.

## v0.2.0 Milestone 3: reviewed proposals

The manual hypothesis flow now separates AI invariant proposal generation, server validation, and local execution. AI output uses a strict semantic proposal schema derived from the invariant plan's safe operation schemas. The canonical invariant capability profile supplies the prompt and bounded source context. The server selects relevant source from validated hypothesis/investigation/invariant evidence and import closure, requires one compatible trusted compiler, injects persisted identity, and runs the existing plan schema and Solidity signature validator before storing a canonical plan hash. Source hashes in proposal history bind later validation to the source the user reviewed.

`executable_invariant_proposals` stores each generation attempt with status, plan/hash when valid, provider/model/prompt, context statistics, usage, duration, and safe failure category. The hypothesis page shows the proposal and limits before enabling explicit validation; the run endpoint accepts only a persisted proposal ID and revalidates it before calling the Milestone 2 service. The existing structured verification path remains separate. No invariant evidence changes hypothesis status.

## v0.2.0 Milestone 4: deterministic replay and reviewed lifecycle

Invariant execution now records `propertyOutcome` separately from `hypothesisRelation`. A held property is neutral to the vulnerability hypothesis. A discovered violation is initially unreviewed. The only supported proposal relationship is `hypothesis-predicts-property-violation`: if the vulnerability hypothesis is true, the property is expected to be breakable. AI explains this relationship but cannot grant evidence authority.

Typed Forge 1.7.1 counterexamples use canonical serialization and SHA-256 identity. Fuzz values are named `uint256`/`bool` values. Stateful cases are ordered action IDs with typed parameter values; generation maps every action back to the original invariant plan. A replay artifact embeds authoritative scan, hypothesis, proposal, run, commit, compiler, invariant-plan, property, parser and counterexample identity. `InvariantReplayGenerator` creates one fixed `testReplay_*` test that passes only when the expected violation is observed. Replay has no fuzzing and accepts no browser-supplied values.

The existing worker protocol has a strict `execute-invariant-replay` branch. Each attempt gets a new replay-run ID and freshly generated workspace; web normalizes the workspace-specific fingerprint back to the immutable artifact ID and checks source, harness, config, replay-plan and counterexample identity before calling the worker. The worker independently regenerates and hashes the workspace, resolves the same trusted compiler, and runs fixed offline `forge test --json` under `prlimit`. Results are `reproduced`, `not-reproduced`, `failed`, or `refused`; a nonzero process exit by itself is never reproduction. Replay artifacts, runs, reviews, authoritative evidence, and lifecycle transitions are immutable linked records. Both historical structured verification and reviewed replay call the same centralized lifecycle authority.
