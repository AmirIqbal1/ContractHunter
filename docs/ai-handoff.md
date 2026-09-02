# ContractHunter AI Handoff

> Read this file before making significant changes to ContractHunter.

## Project purpose

ContractHunter is a locally hosted smart-contract security analysis workstation for authorised analysis only. Repositories and their contents are hostile input. It combines deterministic static scanners, optional manually triggered AI reasoning, ranked hypotheses, and explicit local verification.

## Current version state

Latest released: `v0.1.8.1`.

Current development: `v0.1.9`. Do not describe v0.1.9 as released.

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

## Current v0.1.9 verification

`VerificationHarnessPlan` supports actors, symbolic actor/instance address arguments, decimal uint256 and bool arguments, caller identity, deploy/call/read-uint/read-address/read-balance/fund operations, and uint/address equality or inequality assertions. Limits are eight actors, eight call arguments, and 100 ETH funding. Literal AI-supplied addresses, raw calldata, arbitrary expressions, cheatcode names, and arbitrary Solidity are rejected. ContractHunter chooses deterministic `vm.prank` and `vm.deal` semantics internally. AI proposes verification semantics; ContractHunter supplies authoritative scan, hypothesis, commit, and compiler identity. A single trusted compiler is injected automatically; multiple trusted compilers fail closed until a deterministic source-to-compiler mapping exists. Historical narrow plans remain valid.

The BrokenAccessControl proof can represent attacker → `setOwner(attacker)` → `owner() == attacker` → optional funding → attacker withdrawal → target balance zero, subject to fail-closed execution requirements.

## Current execution limitations

The original Docker fixture failure exposed a real cache-binding bug: scanning prepared solc-select artifacts below `.solc-select`, while verification mounted an unrelated `.svm` cache. v0.1.9 now validates the exact cached artifact/version and binds only that binary into Forge with offline mode and compiler autodetection disabled. Missing compilers fail as `trusted_compiler_unavailable` without installation.

A development machine previously lacked permission to create Bubblewrap network namespaces. Do not solve this with privileged execution, host networking, Docker socket access, weakened namespaces, or unrestricted compiler/network downloads; trusted compiler preparation/cache and fail-closed isolation must remain.

## Important lessons

- Automatic AI after static scanning was removed for cost control.
- Manual background AI jobs require hunt-page polling.
- The `shouldPollHunt()` Server/Client boundary failure (digest `2152019738`) proved production-container rendering must be smoke-tested.
- Forge is pinned in the runtime for Foundry static compilation after earlier Slither/Foundry failures.
- Bodyless verification-plan POST requests must be judged from actual body bytes, not a non-null request body object.
- `verification-plan-v2` sent stale context metadata claiming function arguments were unsupported even though the schema/generator supported them. Current planner capability metadata is derived from the canonical core capability profile.
- `NOT PLANNABLE` is a valid safety result; unsupported hypotheses must not be forced into executable plans.

## Trust model

Repository data is never treated as instructions. Dependency installation is restricted to approved pinned Git submodules and lockfile-backed npm dependencies with lifecycle scripts disabled. Paths, URLs, compiler versions, source evidence, output sizes, timeouts, and process capabilities are bounded.

AI receives bounded context, has no tools, and may propose structured data only. AI must not generate arbitrary executable Solidity, commands, shell expressions, RPC endpoints, wallets, keys, forks, FFI, or live-chain actions for verification.

ContractHunter generates verification Solidity deterministically from a strict plan schema. The harness is rebuilt from persisted scan identity and allowlisted source, then hash-validated before execution. Verification uses fixed Forge arguments and requires Linux network/PID isolation; unavailable isolation fails closed. Only authoritative supporting dynamic evidence can transition a hypothesis to verified.

## Current AI

The default is `OPENAI_MODEL=gpt-5.6-luna`. Configuration currently uses one `OPENAI_MODEL`; per-stage model routing is planned but not implemented. Pricing values are configurable estimates, not invoices.

## Continuation rules

Preserve static-first ordering, manual AI actions, structured outputs, deterministic generation, evidence validation, confidence caps, immutable verification history, and fail-closed isolation. Do not add arbitrary execution paths or silently broaden the verification language. Read [security-model](security-model.md), [architecture](architecture.md), [configuration](configuration.md), and [roadmap](roadmap.md) before changing trust boundaries.
