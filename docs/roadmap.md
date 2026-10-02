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

## v0.2.1 — completed / released

Milestone 1 is implemented as an internal Echidna execution branch in the existing networkless worker. It uses the pinned, locally patched Echidna 2.3.3 compatibility build, strict terminal JSON, a deterministic stateful-plan subset, a separate version 3 manifest, the existing trusted solc resolver, and canonical action-sequence mapping to the existing Foundry replay format. Foundry remains available. No AI prompt, public engine selector, automatic dual execution, or lifecycle policy changes are part of this milestone.

Milestone 2 implements additive public engine persistence, deterministic compatibility reporting, explicit manual Foundry/Echidna actions, normalized run history, and source-engine-bound replay provenance. The v0.2.0-shaped upgrade resolves historical invariant runs and replays as Foundry without changing evidence or hypothesis status. Echidna counterexamples without an exact canonical action mapping remain recorded with replay unavailable. No automatic choice, dual execution, AI engine selection, or lifecycle change is introduced. Echidna's compatible subset remains intentionally narrower than Foundry's.

Milestone 3 hardening is complete. A copied v0.2.0-shaped database retained historical rows and Foundry identity through the upgrade; failures in any pending migration or final validation roll back the whole startup transaction. Separate fresh Compose volumes started with an empty compiler cache and refused missing-solc jobs as `trusted_compiler_unavailable`. Mocked public workflows, malformed-result and tamper cases, retry workspaces, retention policy, and live worker isolation were checked. Isolated real-worker probes covered safe Foundry and Echidna stateful runs, vulnerable Echidna and Foundry counterexamples, Echidna-origin reproduction and explicit review, deliberate non-reproduction without evidence, and the historical Foundry fuzz path. Final release preparation updates the application version to 0.2.1, pins Next.js 16.3.8, and passes the production audit, isolated Compose startup, and live worker smoke. Publishing and tagging remain manual. Caller/setup expansion, fuzz-property Echidna translation, and broader address semantics remain unsupported.

## v0.2.2 — in development

Milestone 1 Part 1 implements an internal, deterministic assessment of four existing verification strategies: structured verification, Foundry fuzz property, Foundry stateful invariant, and Echidna stateful invariant. Bounded facts come only from exact correlated scanner source/rule IDs and resolved investigation contract identity. Canonical profiles reflect current plan capabilities; missing or unmapped evidence produces `unknown`. Results are advisory only: they do not validate a concrete plan, rank strategies, invoke AI, execute verification, or change evidence or hypothesis status.

Milestone 1 Part 2A exposes those four assessments as read-only verification options on each hypothesis page and through a narrow GET endpoint. The public mapper sends only closed strategy, engine, plan-mode, compatibility and reason values with server-owned display text. Compatible options can be selected locally for planning preview; this does not generate a plan, persist a choice, or run a worker. Existing manual generation and execution controls remain available independently.

Milestone 1 Part 2B-1 adds bodyless, explicit strategy-aware server planning. The server recomputes current compatibility before any provider request, reuses the existing structured or invariant planner, constrains invariant mode from the selected enum, and validates the concrete result. Echidna plans must also pass its existing compatibility validator; a failure is recorded without another AI request or Foundry fallback. An additive transactional migration stores selected strategy with invariant proposals and stores immutable structured planning attempts. Existing manual endpoints remain available. Part 2B-2 will connect the UI choice to this route; Part 2B-1 performs no verification execution.

Later work will select appropriate plans using this assessment, then improve hypothesis/property selection and root-cause grouping and deduplication. No automatic engine execution or broader Echidna semantics is included in Part 1.

## v0.3

More autonomous local audit/reporting workflow.

## Future possibilities

Per-stage AI models (including inexpensive Luna triage, a stronger deep-review model, and a separate plan model), additional scanners, Vyper, formal benchmark scoring, local LLM support, CI/PR review mode, and better hypothesis root-cause grouping/deduplication.

## Explicit non-goals

No automatic bounty submission, live exploit deployment, wallet/private-key interaction, or automatic live-chain transactions.
