# Roadmap

## v0.1.9 — current development

Implemented: typed function arguments, actors/caller identity, address reads/assertions, native ETH funding, native balance observations, and stronger structured access-control verification.

Remaining before release: validate a real end-to-end `BrokenAccessControl` plan generation/validation flow against a scan-prepared compiler cache, attempt local verification where isolation permits, complete Docker smoke testing, and perform release hardening/version bump.

## v0.2.0

Executable invariants, Foundry fuzzing, and stateful invariant testing.

## v0.2.1

Echidna integration.

## v0.2.2

Smarter verification-agent and verification-plan selection.

## v0.3

More autonomous local audit/reporting workflow.

## Future possibilities

Per-stage AI models (including inexpensive Luna triage, a stronger deep-review model, and a separate plan model), additional scanners, Vyper, formal benchmark scoring, local LLM support, CI/PR review mode, and better hypothesis root-cause grouping/deduplication.

## Explicit non-goals

No automatic bounty submission, live exploit deployment, wallet/private-key interaction, or automatic live-chain transactions.
