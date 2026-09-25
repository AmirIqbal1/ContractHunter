# Release history

## v0.2.0

Executable invariant plans add bounded Foundry fuzz-property testing and stateful invariant testing with deterministic seeds and configuration. AI can manually propose semantic `invariant-plan-v1` operations, but the server owns scan, hypothesis, commit, compiler, source and canonical-plan identity. Users separately review, validate and run each proposal. The networkless worker independently checks the workspace, trusted compiler and fixed Forge invocation, then a bounded Forge 1.7.1 JSON interpreter records only complete, unambiguous property outcomes.

Counterexamples are parsed into canonical typed values or ordered allowlisted handler actions. Deterministic non-fuzzing replay is generated from persisted evidence, executed in a fresh workspace for every attempt, and remains non-authoritative until an explicit relevance review. Reproduced and reviewed violations create authoritative invariant evidence; only the centralized hypothesis lifecycle can transition an eligible hypothesis to `verified`. Original proposals, runs, failed attempts, replay artifacts, replay attempts, reviews and lifecycle transitions remain immutable.

Release hardening adds transactional recorded SQLite migration from the v0.1.9 data shape, isolated fresh-install and upgrade probes, strict malformed/truncated/exit-inconsistent Forge-output rejection, bounded workspace-retention tooling, retry workspaces, real fuzz/stateful/safe/non-reproducing/lifecycle worker regressions, and a separate v0.1.9 structured-verification regression. Production dependencies were narrowed to patched Next.js 16.3.3 and sharp 0.35.4 after advisory review. The worker remains networkless, non-root, capability-free, read-only-root, one-CPU and 64-task bounded, with FFI/RPC/forks/wallets/private keys and generic command execution unavailable.

Bounded fuzzing is not formal proof. `held-within-bounds` means only that no counterexample was found within the configured runs and depth; it does not prove safety, security, verification, or disprove a vulnerability hypothesis.

## v0.1.9

Broader structured verification plans now support actors and caller identity, typed arguments, address reads/assertions, bounded local ETH funding and balance reads, and recognition of compatible public Solidity getters. ContractHunter supplies scan, hypothesis, commit, and compiler identity from trusted server state, reports more precise plan diagnostics, and generates a deterministic Foundry harness and configuration. The worker binds the exact scan-prepared compiler artifact and runs Forge offline under resource limits through a dedicated networkless container and bounded Unix-domain socket protocol. Web-owned deterministic interpretation produces dynamic evidence; only completed, confirmed runs with valid supporting evidence can transition a hypothesis to `verified`.

The real BrokenAccessControl benchmark plan (`verification-plan-v4`) completed with trusted solc 0.8.36: one Forge test passed, four supporting dynamic evidence items were produced, and the hypothesis became `verified`. This demonstrates that case; it does not establish dynamic coverage of the other benchmark families. Hostile repository content remains data. Verification has no live RPC, wallets/private keys, FFI, arbitrary AI-generated commands, Docker socket, or network access, and fails closed when its worker, isolation, workspace, or trusted compiler is unavailable. Nested Bubblewrap and its custom Docker profiles were investigated during development, then retired before release.

A one-shot, non-root data initializer prepares the trusted-cache directory before the worker starts on fresh Docker volumes, including an empty root-owned subpath Docker may create during container creation; it leaves populated compiler caches intact.

## v0.1.8.1

Static-first scanning, optional/manual AI analysis and security review, background polling, cost/usage visibility, stale-scan recovery, improved progress state, Slither Foundry/Forge support, multi-scanner correlation, and duplicate-request safeguards. The production hunt-page Server/Client polling boundary is fixed. Verification remains explicit, deterministic, structured, and fail-closed.

## v0.1.8

Review-first local hypothesis verification with deterministic Foundry harnesses, manifests, hashes, structured dynamic evidence, and confirmed/refuted/inconclusive outcomes. No arbitrary Solidity, commands, RPC, wallets, forks, FFI, or live-chain execution.

## v0.1.7

Specialist AI security reviewers and ranked hypotheses with bounded context, structured output, evidence validation, confidence caps, and no automatic verification. Hypotheses were not verified vulnerabilities.

## v0.1.6

Optional AI protocol understanding and proposed invariants with bounded hostile-data context, no tools/code execution, validated evidence, and manual invariant acceptance.

## v0.1.5

Deterministic Slither/Aderyn cross-scanner correlation into investigations. Raw findings remained available and static agreement never verified a vulnerability.

## v0.1.4

Aderyn integration alongside Slither. Per-scanner failures were isolated and successful results preserved.

## v0.1.3

Safe preparation of pinned Git submodules and lockfile-backed npm dependencies. Lifecycle scripts and unsupported dependency sources were rejected.
