# Release history

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

## Unreleased — v0.1.9 development

Implemented structured local verification coverage: typed function arguments, explicit actors and caller identity, address reads/assertions, bounded local ETH funding, native balance observations, deterministic dynamic evidence, and backward-compatible historical plans. `BrokenAccessControl` is now structurally plannable. The verification-plan empty-body request bug fix is also present.

v0.1.9 is not released. Compiler hardening now resolves the exact scan-prepared solc-select artifact, verifies its version, and read-only binds that binary into offline Forge. Missing or invalid cache entries return `trusted_compiler_unavailable`; verification never downloads a compiler. A real Docker Forge smoke still requires a compiler prepared through the normal scan policy and working local isolation.
