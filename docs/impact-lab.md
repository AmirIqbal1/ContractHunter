# ContractHunter v0.3 — Fork & Impact Engine

**User-facing workflow:** Impact Lab. **Status:** v0.3 Phase A1 internal fork lifecycle and safety boundary implemented; v0.3 is not released. No PoC execution, result export, public API, CLI, or GUI exists yet.

## Phase A1 implementation

`packages/core/src/impact-fork.ts` defines strict finding/hypothesis linkage, chain and network identity, an exact required fork block, target addresses, an `IMPACT_RPC_*` secret reference, and fixed `127.0.0.1` binding. The server resolves the upstream URL only at runtime. `packages/scanners/src/impact-upstream-proxy.ts` creates a random-path loopback proxy and forwards only positively listed read methods; it rejects transaction submission, wallet/admin mutation, malformed or mixed JSON-RPC batches before forwarding, refuses redirects, and bounds request/response size and time. Anvil receives only this proxy URL, never the provider URL or key. This is an application-level filter; Phase A2 must independently constrain egress from any future PoC runtime.

`ImpactForkService` resolves only approved local Anvil paths, checks file ownership/mode and SHA-256, and invokes a fixed Anvil argument vector without a shell or inherited wallet environment. Linux `setpriv --pdeathsig SIGKILL` and a dedicated process group provide parent-crash and explicit-stop cleanup. Anvil binds `127.0.0.1` on a selected ephemeral port. Before ready, the service compares upstream and local chain ID and the exact pinned block hash, checks Anvil client identity, verifies that the owned PID/start token holds the loopback listener socket, reads one Anvil development account address, and creates a baseline snapshot. The central `assertSafeImpactExecutionEndpoint` repeats process, listener, chain, client, and block-hash checks before every local control operation. A localhost address alone is never authority.

The internal service supports additional snapshots, revert, reset to baseline, and address-validated impersonation/stop-impersonation only through that guard. It limits concurrent starting/ready sessions to two, lifetime to 30 minutes, startup to 15 seconds, and captured process output to 64 KiB. Failed readiness, snapshot, or endpoint checks fail closed and attempt process-group cleanup. Migration `0009_v0_3_impact_fork_sessions` stores audit identity, status, port, tool hash/version, block hash, and account addresses but no process handles, upstream URLs, provider secrets, mnemonics, or private keys. Runtime handles and random session tokens remain in memory; persisted active rows are marked failed on restart and cannot authorize RPC use.

There is no public Impact Lab route or generic raw RPC passthrough. The default Compose image does not provision Anvil in A1; a trusted approved local Anvil executable must already exist for a real lifecycle run. No executable was downloaded or installed during this phase.

Impact Lab lets an authorised researcher reproduce a candidate smart-contract vulnerability against a **local fork of pinned deployed state**, measure the observed consequences, and retain reproducible evidence. It follows the existing pipeline:

```text
Static analysis → architecture, roles and call graph → invariant/fuzz verification
→ candidate vulnerability → Impact Lab → local blockchain fork
→ controlled PoC → trace, state diff and asset flow → impact evidence → export
```

It does not replace structured Foundry verification, Echidna, counterexample replay, relevance review or centralized hypothesis lifecycle authority. Starting an experiment is explicit. Reproduction outcome, impact estimate and hypothesis status remain separate until a later authoritative-evidence policy is designed.

## Engine and chain scope

Use Foundry **Anvil** as the default local fork engine; do not build a custom blockchain emulator. Begin with Ethereum, Arbitrum, Base, Optimism and Polygon when the configured RPC and pinned Anvil version support the required fork behavior. Record chain ID, network, target deployment, exact fork block and block hash, Anvil/tool versions and configuration for every experiment. Treat chain-specific behavior as an explicit compatibility check, not an assumption. Keep support extensible. The engine is local-first and open-source-first; Tenderly is at most a later optional integration.

The engine/domain schema precedes its interfaces. An experiment will conceptually bind a finding or hypothesis, chain/fork identity, target contracts, disposable attacker identity, scenario, privilege and flash-liquidity requirements, reviewed PoC identity, transaction hashes, execution outcome, selected initial/final state, affected contracts/storage, call trace, asset movements, protocol loss, attacker net gain, timestamp and reproducibility status. Final field names and evidence authority require design review. One canonical experiment/result model should serve a CLI or internal service, then an API, then the web GUI.

## Fork and RPC safety boundary

There are two distinct endpoints:

| Endpoint | Purpose | Authority |
| --- | --- | --- |
| **Live upstream RPC** | Supply historical fork/read state at a pinned block | Read-only proxy/filter; no PoC access or transaction submission |
| **Local execution RPC** | ContractHunter-managed Anvil sandbox bound to localhost | The only endpoint available to reviewed PoC execution |

The PoC sandbox must not receive the upstream URL, upstream credentials, a route that bypasses the filter, or the user's real private keys. Use disposable attacker/test accounts. Block upstream transaction-submission methods with a positive read-method allowlist, including JSON-RPC batches and provider-specific submission variants; validate redirects and egress paths. Investigate a read-only upstream proxy/filter and independent network controls so a malformed PoC cannot send a live transaction. Before any destructive local action, verify the execution endpoint is the expected ContractHunter-managed Anvil instance with the expected chain and fork identity; reject an unsafe or nonlocal endpoint and fail closed on uncertainty. Pin the fork block rather than following the live head.

The current verification worker is intentionally networkless and stays separate. Impact Lab needs its own bounded runtime with narrowly scoped upstream read access and local execution only. Account impersonation, native funding and time/block manipulation are useful local-fork controls, but must be explicit, auditable scenario inputs. Record whether a reproduction is permissionless, admin/governance-only, a compromised-key scenario or an access-control misconfiguration. A result requiring impersonation must not be presented as a permissionless exploit.

Anvil documents pinned-block forking, impersonation, state control and tracing in its [official overview](https://getfoundry.sh/anvil/). Ethereum's [JSON-RPC reference](https://ethereum.org/developers/docs/apis/json-rpc/) distinguishes read calls from transaction-submission methods; the implementation must still review the exact provider method surface and test the filter rather than rely on a short denylist.

## Incremental milestones

### 1. Fork safety and Anvil lifecycle

Define bounded chain and RPC references, target deployment, exact fork block and finding linkage. Start and stop isolated Anvil on localhost; verify health, identity, chain and block. Create disposable accounts. Support snapshot/revert/reset and carefully scoped impersonation, time and block changes. Establish the upstream read-only transaction-blocking boundary before running PoCs.

### 2. Controlled PoC execution

Start with manually supplied and reviewed Forge PoCs. Link finding → fork configuration → isolated Anvil → bounded Forge run against the verified local endpoint → structured result. Pin versions, limits and scenario inputs; capture failures as well as successes. Autonomous exploit generation is not a prerequisite.

### 3. State capture and diff

Capture selected state before and after each run: native balances, contract ETH, ERC-20 balances, ERC-721 ownership, ERC-1155 balances, selected storage, protocol accounting values and important view results. Store typed observations and explicit unknowns; avoid indiscriminate storage dumps.

### 4. Transaction and call tracing

Normalize available Anvil/Foundry traces into a bounded call tree, transaction order and relevant call annotations. Keep trace data independent of presentation so CLI, API and GUI can consume it consistently.

### 5. Asset-flow and impact analysis

Represent transfers and participants as graph-ready data. Where observable, account for asset types, addresses, attacker net gain, protocol loss, fees and flash-loan repayment. Record valuation method and uncertainty; asset movement alone does not prove vulnerability validity or justify a lifecycle transition.

### 6. Reproducibility and evidence export

Bind each experiment to immutable inputs and artifacts, support replay/reset, and export a technical bounty evidence bundle such as:

```text
impact/
  finding.json
  impact.json
  fork.json
  trace.json
  asset-flow.json
  state-before.json
  state-after.json
  state-diff.json
  transactions.json
  poc.t.sol
  report.md
```

The report should describe deployment and chain, fork block, prerequisites, required privilege, reproduction steps, observed consequence, protocol loss and attacker gain, affected contracts, state changes, transaction trace and PoC. Exports must omit upstream credentials and private keys. Design toward a later `contracthunter impact replay <finding-id>` command; its exact interface and artifact format remain open.

### 7. Impact Lab GUI

After the engine and service/API boundaries are reliable, add a technical view to the existing web application: finding, network, block, deployment, outcome, privilege and flash-liquidity requirements, selected state before/after, trace, diff, asset flow, scenarios, replay/reset and export. The UI presents engine-owned structured facts rather than deriving impact itself.

## Bounded scenarios and future autonomy

The first scenario runner needs only controlled, explicit inputs. Later scenarios may compare normal users, different capital levels, flash liquidity, repeated exploitation, different callers, privileged callers and non-privileged callers. Each result retains its scenario and prerequisite labels. Do not build an optimization or search engine in the first implementation.

After the reliable engine exists, later v0.3.x or future work may propose bounded Forge PoCs from candidate findings, execute them **only** on Impact Lab's local fork, inspect failed traces, revise within strict request/run limits and retain confirmed local reproduction. More autonomous audit orchestration and report generation follow the same boundary. AI output cannot choose a live execution endpoint or acquire real signing keys.

## Testing and acceptance direction

CI should use deterministic local/test contracts and controlled fork fixtures; public RPC availability cannot be the sole test dependency. Milestone tests should cover Anvil startup/shutdown, local fork creation, exact block pinning, snapshot/revert, impersonation, disposable accounts, localhost-only execution, nonlocal RPC rejection, upstream submission blocking (including batches), PoC execution, state capture/diff, balance tracking, traces, asset-flow calculations, export, replay and cleanup after failure. Narrow live-network compatibility probes can supplement deterministic tests but cannot establish the safety boundary by themselves.

Impact Lab evidence eventually needs an explicit bridge to ContractHunter's authoritative evidence and centralized lifecycle model. Neither `exploitSucceeded` on a fork nor a calculated loss automatically means a hypothesis is `verified`; that policy remains a separate design milestone.
