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

The worker reuses the trusted compiler resolver and executes `/usr/local/bin/forge test --json` inside the workspace via `prlimit`, offline and without FFI. Forge 1.7.1 rejects combining `--json` and `--color never`; `NO_COLOR=1` remains set in the worker-owned environment. The bounded JSON parser requires the expected generated test names and mode-specific results. Web maps each result to `held-within-bounds` or `counterexample-found` evidence. A separate `executable_invariant_runs` table records immutable runs and evidence without updating hypothesis status. An internal service starts execution; there is no public invariant endpoint or UI yet.
