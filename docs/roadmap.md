# Roadmap

## v0.1.9 — completed

Delivered: typed function arguments, actors/caller identity, address reads/assertions, native ETH funding, native balance observations, and stronger structured access-control verification through the networkless worker.

The real BrokenAccessControl plan was validated and verified with trusted solc 0.8.36: one Forge test passed and supporting dynamic evidence changed the hypothesis to `verified`.

## v0.2.0 — in development

Milestone 1 adds an internal, versioned `ExecutableInvariantPlan` for bounded fuzz properties and stateful invariants. Trusted, manually constructed plans can generate Solidity, an offline Foundry configuration, and a hashed workspace manifest deterministically. Small accounting and access-control fixtures plus offline tests exercise these foundations. Invariant worker execution, dynamic evidence, AI planning, and UI controls remain future milestones.

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

