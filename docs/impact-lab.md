# ContractHunter v0.3 — Fork & Impact Engine

**User-facing workflow:** Impact Lab. **Status:** v0.3 Phase A3 fork compatibility and isolated probe-runtime foundation implemented; v0.3 is not released. No vulnerability PoC execution, result export, CLI, or GUI exists yet.

## Phase A3: real fork and isolated probe runtime

The deterministic integration uses two checksum-verified Foundry Anvil 1.7.1 processes. Upstream fixture A has chain ID 31337, two disposable accounts, a tiny non-vulnerable contract whose runtime bytecode reads storage slot zero, and an exact mined block. Fixture-only `anvil_setCode`, `anvil_setStorageAt`, and `anvil_mine` prepare A before the proxy starts; these calls are never sent through the proxy. Fork B receives only the private read-only proxy URL and the exact block number. ContractHunter's normal ready-state proof confirms the same chain, block hash, deployed-code SHA-256, and baseline snapshot. The test confirms storage and `eth_call` return the fixture value, sends one harmless transfer **only to B**, then reverts B's snapshot. A's code, storage and balance remain unchanged. Neither a production provider nor a user wallet participates.

The real fork forwarded only `eth_chainId`, `eth_gasPrice`, `eth_getBalance`, `eth_getBlockByNumber`, `eth_getCode`, `eth_getStorageAt`, and `eth_getTransactionCount`. Anvil also attempted `eth_getAccountInfo`; the proxy rejected it, and Anvil successfully fell back to the allowed reads. No transaction, signing, `personal_*`, `anvil_*`, `hardhat_*`, `wallet_*`, or `evm_*` method was forwarded. The A2 18-method allowlist is unchanged: this one EVM fixture proves the seven observed methods, but cannot prove other historical-block, proof, log, receipt, or fee methods unnecessary for all supported chains and lazy-read paths. The remaining methods are narrowly read-only: `eth_blockNumber` resolves a numeric head; `eth_getBlockByHash` looks up a pinned block; `eth_call` reads contract state; `eth_getLogs` and `eth_getBlockReceipts` read block events/receipts; `eth_getTransactionByHash` and `eth_getTransactionReceipt` read transaction history; `eth_getProof` reads account/storage proof; `eth_feeHistory` and `eth_maxPriorityFeePerGas` read fee estimates; `net_version` reads network identity. The observed seven read chain identity, gas price, balance, block, code, storage, and nonce respectively. Any proposed removal needs a broader chain/lazy-read compatibility test. No mutation method was added.

`ImpactPoCRuntimeService` is a separate internal foundation for Phase B. It accepts only a verified `sessionId`, resolves the current in-memory fork handle, passes the central execution guard, and binds a runtime to the handle token hash. Docker runs a fixed image **ID** with schema label `v1`; the base is digest-pinned. The container has `--network none`, so it has only loopback and no IP route to the host, LAN, proxy, upstream or internet. Its sole mount is one read-only bind of a per-session Unix-domain socket. ContractHunter's host-side bridge rechecks the current token and fork guard on each request and, in A3, permits only six bounded read methods against the assigned fork. There is no network transit through Anvil or proxy, no DNS route, no Docker socket, database, repository store, wallet, provider secret, arbitrary image, command, environment or endpoint input. Each session has a distinct socket; a container for session A has no mount for session B. A fork stop/recreate invalidates the old token and tears down the associated runtime. Startup removes labeled stale probe containers rather than trusting persisted runtime metadata. Runtime status is memory-only; migration `0010` remains latest.

The live Docker probe inspected `network none`, the single socket mount, nonroot UID, read-only root, dropped capabilities, no-new-privileges, 32-PID and 0.5-CPU limits, 128 MiB memory limit, default Docker seccomp/AppArmor, and absence of sensitive mounts/environment. It reached its assigned verified fork via the socket. TCP attempts to the upstream proxy, both fork listeners, a deliberately open host-gateway listener, and a public IP failed; the other session's socket was absent. These probes execute no PoC or Solidity. The host controller currently needs Docker CLI/daemon access and is exercised as a local internal harness; the standard Compose web service does not yet provide a production orchestration channel. Stale-container reaping assumes one ContractHunter Impact Lab controller per Docker daemon. The A3 safety proof therefore does not itself publish a PoC execution workflow. Phase B must add a trusted controller/deployment path and expand the guarded local bridge only for reviewed, bounded PoC operations.


## Phase A2: exact-block fork sessions

Phase A2 keeps Anvil behind the ContractHunter-owned loopback read-only JSON-RPC proxy. The browser selects a server-configured `rpcConfigId`; `IMPACT_RPC_CONFIGS` maps that ID to a chain ID, network and `IMPACT_RPC_*` environment secret reference. Neither the raw URL nor the secret reference is returned by the public session serializer. The proxy accepts POST on a random private loopback path only. Its whole-batch positive allowlist is `eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getCode`, `eth_getBalance`, `eth_call`, `eth_getStorageAt`, `eth_getLogs`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getTransactionCount`, `eth_getProof`, `eth_feeHistory`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_getBlockReceipts`, and `net_version`. Unknown, signing, wallet, account, mining, impersonation, snapshot, Anvil/Hardhat mutation and transaction-submission methods are rejected before forwarding. Mixed batches are rejected in full.

The proxy bounds requests to 256 KiB, responses to 4 MiB, batches to 20 calls, methods to 64 characters, concurrent requests to eight, and upstream calls to ten seconds. Malformed JSON-RPC is rejected. Redirects are refused and provider errors are replaced with a generic error so secret-bearing URL text is not exposed. A configured URL must be HTTPS, without URL credentials or fragments; configuration is a privileged server setting, not browser input. No RPC cache is used.

Before Anvil starts, the service checks the configured chain ID, resolves the exact block and hash, and verifies nonempty deployed code for every target at that block. Deployed-code identity is `sha256:` plus SHA-256 of the bytecode bytes; it is separate from source hashes. Anvil receives only the proxy URL and exact block in a fixed argument vector. Before ready, the owned loopback Anvil process must report the expected chain and block hash, target code hashes must equal the upstream hashes, and a baseline snapshot must succeed. The central execution guard repeats process/listener, proxy, chain, block and target-code checks. The proxy and unrelated local RPC are never execution endpoints.

Migration `0010_v0_3_impact_fork_identity` adds nullable configuration ID and target-code-hash fields. Historical A1 rows retain null/empty identity rather than fabricated data. A stopped or failed A2 session can be recreated explicitly with the same persistent session ID, a fresh runtime token/process/port and fresh baseline snapshot. Recreation re-resolves its configured secret reference and fails if the chain, saved block hash or saved target code hash changed. Server startup does not recreate sessions. The public API offers configured RPC references, create, inspect, stop and explicit recreate routes. It exposes no raw execution RPC, process ID or provider secret.

At the A2 milestone, tests used a deterministic fake read provider that recorded received methods and proved transaction methods and mixed batches never reached it. No approved Anvil executable or Impact Lab test RPC was then available. A3 supplied a checksum-verified local Anvil from the existing Foundry build cache and completed the real-fork and live isolation proofs above. No third-party test RPC was configured; no vulnerability PoC or autonomous exploit generation exists.

## Phase A1 implementation

`packages/core/src/impact-fork.ts` defines strict finding/hypothesis linkage, chain and network identity, an exact required fork block, target addresses, an `IMPACT_RPC_*` secret reference, and fixed `127.0.0.1` binding. The server resolves the upstream URL only at runtime. `packages/scanners/src/impact-upstream-proxy.ts` creates a random-path loopback proxy and forwards only positively listed read methods; it rejects transaction submission, wallet/admin mutation, malformed or mixed JSON-RPC batches before forwarding, refuses redirects, and bounds request/response size and time. Anvil receives only this proxy URL, never the provider URL or key. A3 adds independent networkless isolation for the separate probe runtime.

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
