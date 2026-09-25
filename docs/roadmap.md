# Roadmap

## v0.1.9 — completed

Delivered: typed function arguments, actors/caller identity, address reads/assertions, native ETH funding, native balance observations, and stronger structured access-control verification through the networkless worker.

The real BrokenAccessControl plan was validated and verified with trusted solc 0.8.36: one Forge test passed and supporting dynamic evidence changed the hypothesis to `verified`.

## v0.2.0 — completed / release-ready

Milestone 1 adds an internal, versioned `ExecutableInvariantPlan` for bounded fuzz properties and stateful invariants. Trusted, manually constructed plans generate Solidity, an offline Foundry configuration, and a hashed workspace manifest deterministically.

Milestone 2 executes those workspaces through the existing networkless verification worker. The worker independently revalidates the embedded structured plan, source closure, generated harness, config, manifest identity and trusted compiler, then runs fixed `forge test --json` under invariant-specific resource limits. Web interprets bounded Forge 1.7.1 facts into supporting or contradicting dynamic evidence and stores immutable invariant run history. Synthetic vulnerable accounting and stateful access-control fixtures produced counterexamples; the safe accounting control found none within 128 configured fuzz runs. The historical single-path verification flow remains separate.

Milestone 3 adds manual, one-shot AI invariant proposals. A strict semantic schema excludes scan/hypothesis IDs, commit, compiler, paths and executable content. The server composes and validates a canonical plan from persisted evidence, records every proposal attempt, and requires separate user actions to validate and run it. The hypothesis page presents a reviewable plan and bounded execution evidence alongside the existing structured verification workflow. A passing bounded fuzz run is a neutral property outcome, not formal proof or authoritative hypothesis evidence. Invariant proposals and results do not change hypothesis status.

Milestone 4 separates property outcomes from hypothesis relations. Counterexamples remain unreviewed observations until ContractHunter generates a fixed, non-fuzzing replay from persisted typed values, the networkless worker reproduces the expected property violation, and the user explicitly confirms its relevance. That review creates authoritative supporting dynamic evidence and the centralized lifecycle authority may move an eligible candidate to verified while recording an immutable transition. Held-within-bounds, unreplayed, failed, refused, and not-reproduced results never change status.

Release hardening completed transactional v0.1.9 migration, fresh-install and upgrade probes, UI component plus SSR/API workflow QA, fresh retry workspaces, conservative workspace-retention tooling, malformed Forge-output regression coverage, real replay/lifecycle probes, legacy structured-verification regression, and final worker/API trust-boundary review. Broader invariant semantics, inverse hypothesis relationships, multi-counterexample selection, and autonomous execution remain out of scope.

## v0.2.1 — next target

Echidna integration.

## v0.2.2

Smarter verification / plan selection / root-cause grouping.

## v0.3

More autonomous local audit/reporting workflow.

## Future possibilities

Per-stage AI models (including inexpensive Luna triage, a stronger deep-review model, and a separate plan model), additional scanners, Vyper, formal benchmark scoring, local LLM support, CI/PR review mode, and better hypothesis root-cause grouping/deduplication.

## Explicit non-goals

No automatic bounty submission, live exploit deployment, wallet/private-key interaction, or automatic live-chain transactions.
