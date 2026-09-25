# Roadmap

## v0.1.9 — completed

Delivered: typed function arguments, actors/caller identity, address reads/assertions, native ETH funding, native balance observations, and stronger structured access-control verification through the networkless worker.

The real BrokenAccessControl plan was validated and verified with trusted solc 0.8.36: one Forge test passed and supporting dynamic evidence changed the hypothesis to `verified`.

## v0.2.0 — in development

Milestone 1 adds an internal, versioned `ExecutableInvariantPlan` for bounded fuzz properties and stateful invariants. Trusted, manually constructed plans generate Solidity, an offline Foundry configuration, and a hashed workspace manifest deterministically.

Milestone 2 executes those workspaces through the existing networkless verification worker. The worker independently revalidates the embedded structured plan, source closure, generated harness, config, manifest identity and trusted compiler, then runs fixed `forge test --json` under invariant-specific resource limits. Web interprets bounded Forge 1.7.1 facts into supporting or contradicting dynamic evidence and stores immutable invariant run history. Synthetic vulnerable accounting and stateful access-control fixtures produced counterexamples; the safe accounting control found none within 128 configured fuzz runs. The historical single-path verification flow remains separate.

Milestone 3 adds manual, one-shot AI invariant proposals. A strict semantic schema excludes scan/hypothesis IDs, commit, compiler, paths and executable content. The server composes and validates a canonical plan from persisted evidence, records every proposal attempt, and requires separate user actions to validate and run it. The hypothesis page presents a reviewable plan and bounded execution evidence alongside the existing structured verification workflow. A passing bounded fuzz run is supporting evidence, not formal proof. Invariant proposals and results do not change hypothesis status.

Automatic hypothesis status policy, broader invariant semantics, and any autonomous execution remain future work.

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
