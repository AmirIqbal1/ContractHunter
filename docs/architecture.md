# Architecture

```text
apps/web          Next.js UI, API routes, scanning runner, verification planner/interpreter
packages/core     Domain models, Zod schemas, configuration, safety rules
packages/db       Drizzle schema and SQLite repository functions
packages/scanners Dependency/compiler managers, scanners, parsers, workspace builder, worker protocol
docker/verification-worker.ts  Networkless deterministic Forge and Echidna controller
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

## v0.2.1 Milestone 1: Echidna compatibility engine

Foundry remains the historical invariant engine. A separate `execute-echidna-invariant` worker operation accepts bounded identities and a canonical plan hash. Its version 3 manifest embeds the plan, source closure, deterministic harness/configuration hashes, seed, exact Echidna 2.3.3 compatibility build ID and binary hash, compiler identity, and fixed limits. The worker regenerates the harness and config, rejects extra files and symlinks, resolves the same cached trusted solc, then invokes `/opt/contracthunter/echidna/echidna` with a fixed argv under the existing `prlimit` and container isolation. The patched binary emits one strict JSON document with typed property names, terminal outcomes, stop reason, seed, and bounded transactions. The worker parser cross-checks property set, seed, version, outcome, and exit code.

The initial compatibility validator supports stateful plans with one no-argument deployment, generated uint256/bool actions, and current uint/balance equality assertions. It accepts multiple properties. It rejects actors, explicit callers, setup calls/funding, address assertions, caller/environment-sensitive source, and fuzz-property mode with explicit reasons. No plan supplied Solidity or Echidna config is used. The deterministic seed is the first 48 bits of the canonical SHA-256 plan hash. Exact zero-value, zero-delay Echidna action sequences map to the existing canonical counterexample type and Foundry replay generator; otherwise replay availability is false while the property failure remains recorded. A bounded held result is neutral to the hypothesis, and all existing relevance and lifecycle rules remain unchanged.

The compatible binary is built from the included upstream v2.3.3 archive and a four-file output patch using upstream's locked Nix flake. A serial build yielded byte-identical static ELF hashes in two clean containers. The worker image also carries a hash-locked Python `crytic-compile` runtime to invoke the exact trusted solc path. See `third_party/echidna/README.md` for source, build, hash, and license details. This milestone exposes an internal builder/client path only; AI and UI do not choose the engine.

## v0.2.1 Milestone 2: manual public selection

The existing invariant proposal validation now returns Foundry compatibility and the narrow Echidna validator's bounded reason codes. The UI shows two manual engine actions only after validation. The Foundry action retains its historical route as an alias; the Echidna action revalidates persisted proposal, source hashes, scan/commit/compiler identity, canonical plan, and compatibility before building a workspace. It invokes only `execute-echidna-invariant` through the existing worker client. Each action appends a separate run with explicit `engine` and `proposal_id` columns; old rows receive the Foundry default and retain nullable historical proposal IDs in transactional migrations. Foundry runs store parser/tool/config identity; Echidna runs store bounded build/config/harness/seed audit metadata.

Both engines expose the same property outcomes and separate hypothesis relations. An exact Echidna sequence enters the existing deterministic Foundry replay service. Replay artifacts bind source engine, invariant run ID, and counterexample hash; historical Foundry plans retain their original hashes. Reproduction plus explicit relevance review still enters the single centralized lifecycle authority. A non-mappable Echidna sequence remains a `counterexample-found` observation with replay unavailable.
## v0.2.1 Milestone 3 Part 1 hardening

Startup now places every pending schema migration and database validation in one outer SQLite transaction. Public history maps completed runs only when persisted engine, plan, evidence, compiler, and Echidna seed agree. Replay execution binds source engine, run, proposal, commit, compiler, plan and counterexample to persisted authoritative records before creating a fresh worker attempt. Foundry stateful counterexamples use Forge's raw typed argument field when its display field contains formatted notation. The operator retention helper recognizes Echidna's version 3 manifest and refuses unknown or symlinked workspace trees. No engine semantics or lifecycle policy expanded.
