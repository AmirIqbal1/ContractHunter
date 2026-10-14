# ContractHunter v0.3 — Fork & Impact Engine

## Phase E1 deterministic asset-flow accounting — implemented

`contracthunter-asset-flow-v1` uses ruleset `contracthunter-asset-accounting-v1` to derive one immutable-by-content, frontend-independent accounting result from an exact reviewed local execution's Phase 10 overlay. The service repeats the scan/execution/subject/session binding and reads only persisted C1 and D1 evidence. It derives on read, adds no migration, and makes no RPC call or transaction. Phase E2 Visual Asset Flow is next; full Phase E and Phase F are not implemented.

The canonical ledger contains **committed** movements only: successful CALL/CREATE/CREATE2 nonzero native value from the D1 tree, and exact committed receipt-log Transfer, TransferSingle and bounded TransferBatch facts. A reverted transaction commits none of its apparent state-transfer effects. A reverted call, or a successful child beneath a reverted ancestor, is kept as an attempted native flow. Delegatecall, callcode and selfdestruct do not become native transfers without authoritative movement semantics. ERC20 `transfer` function names and static source operations are context only. Repeated identical logs remain distinct by log identity. Native trace preorder and receipt-log order are separate domains; no combined chronology is invented.

Assets use chain ID, standard, token contract and token ID where applicable. Participants retain exact addresses and only authoritative labels: disposable PoC sender from the bound session, transaction sender, mapped protocol contract, zero address or unmapped address. A zero-address Transfer remains a transfer fact, not a protocol mint/burn conclusion. Gross incoming/outgoing and net observed movement use exact BigInt arithmetic and raw units; no token price, fiat conversion, scenario role, profit, protocol loss or severity is derived. Arbitrary storage is not an asset.

ERC20 and ERC721 share a Transfer signature. E1 accepts a token standard only from a trusted server-side classification witness; the current production adapter has none. A valid ambiguous Transfer is retained as `token-transfer-unknown-standard`, with its exact event shape and participants, rather than guessed as ERC20 or ERC721. ERC1155 single/batch signatures are decoded strictly; malformed, truncated or oversized batches yield a warning and no partial invented entries. ERC721 ownerOf and fungible PRE/POST balances are net observations; totalSupply is context. The ledger is directional event/call evidence, while snapshots are net state evidence. Reconciliation compares them only where semantically comparable and records reconciled, partial, mismatch, insufficient or unavailable status with coverage. Differences may reflect fees, rebasing, unobserved accounts or unsupported behavior; they are not vulnerability findings. No full conservation claim is made.

D1 persists gas used but not effective gas price, so exact execution gas cost is explicitly unavailable and stays outside the transfer ledger. Native sender PRE/POST balances may include gas and cannot be fully reconciled from value calls alone. Older executions without C1/D1 report capability flags and unavailable or partial accounting. Content identity binds execution, overlay, C1/D1 hashes, ruleset and any trusted standard evidence. The read-only API returns no private key, RPC URL/credential, runtime token, worker secret, Docker control or host path. Phase 10 overlay, ProtocolGraph, finding/hypothesis authority and Impact Lab execution authority remain unchanged.

## Phase 10B visual dynamic overlays — implemented

Finding and Hypothesis pages link an exact reviewed PoC execution to the read-only Observed Local Execution page and the Phase 9 Investigation Path. The path page offers Static Investigation, Observed Execution and Compare modes. The static path retains its canonical identity. Compare labels exact edge matches **OBSERVED IN THIS LOCAL EXECUTION**, comparable absent edges **NOT OBSERVED IN THIS EXECUTION**, and incomplete mapping **UNAVAILABLE**. A single reproduction does not prove a path can never execute. Multiple paths and executions remain distinct.

Every runtime view says **LOCAL FORK** and explains that it came from a reviewed PoC executed against ContractHunter's isolated local fork. The selected transaction has its own hash, sender, target, value, receipt status, local block and gas. Its ordered D1 call tree shows bounded input/output previews, byte counts, hashes, mapping status, source only for exact mapping, delegatecall code/storage context, and reverted calls. CREATE/CREATE2/SELFDESTRUCT are shown as observed operations when present. Large traces start with a bounded visible portion and can be expanded; search and filters change presentation only. Logs remain transaction-specific. Protocol Map can add dashed, labeled observed edges and ephemeral runtime target nodes with overlay-specific IDs; its static graph remains unchanged.

Observed State Changes groups native balances, ERC20 raw units, ERC721 owners, ERC1155 amounts, storage slots and supported views. Changed is the default; unchanged, unavailable and category filters retain underlying observations. PRE/POST values and meaningful C1 decimal deltas stay exact. Unknown storage slots are not named, event declarations are not guessed, and a state change is only described as observed during the execution. Historical or partial trace/state capture is visibly unavailable. Function Explorer keeps SOURCE-ORDER VIEW separate from OBSERVED RUNTIME ORDER and only attaches calls proven to map to its exact function. Beginner and Researcher expose the same facts at different detail levels.

Production still lacks an authoritative deployed-bytecode-to-source witness. Most current calls therefore have unresolved canonical contract/function identity, and static edge comparisons cannot claim matches. Phase 10B adds no PoC execution, evidence admission, finding/hypothesis lifecycle mutation, RPC call, AI inference or financial impact calculation. E1 accounting is now implemented as a separate read model; E2 Visual Asset Flow is next.

## Phase 10A deterministic Impact Overlay

`contracthunter-impact-overlay-v1` and deriver `contracthunter-impact-overlay-deriver-v1` provide a frontend-independent read model for one exact reviewed PoC execution. The server binds the execution to its artifact, session, scan-owned finding/hypothesis, local fork base identity, source hash, runtime-token hash internally, target code hashes, C1 snapshot/diff IDs and D1 trace IDs/content hashes. Its canonical content hash also binds the static graph/path content identity and mapping rule version. It is derived on read; no new storage or migration was needed. The narrow GET endpoint is documented in [API](api.md).

The model preserves each **OBSERVED TRANSACTION** and its local block/hash separately from the original fork block/hash, ordered **OBSERVED CALL** trees, **OBSERVED LOGS**, and C1 **OBSERVED STATE CHANGE** records. C1 native/ERC20/ERC1155 integer deltas remain decimal strings, ERC721 owners remain exact owner observations, storage remains exact slot/word unless an authoritative layout is available, and unavailable reads never become zero. Unchanged observations remain available. Reverted receipts and trace evidence remain; failed or historical capture is explicit. D1 trace order is local runtime order, while Function Explorer source order is static syntax order. Calls and state changes in one execution are not asserted to cause each other. A later comparison can select another exact execution without merging evidence.

`compareInvestigationPathToImpactOverlay` uses canonical graph node/edge IDs: exact mapped call edges can be marked “observed in this local execution.” A comparable edge absent from a complete, exactly mapped capture is “not observed in this execution,” never unreachable. Missing traces or unmapped calls make unmatched comparisons unresolved; privilege/oracle and other non-call relationships remain static context only. Runtime-only observed calls are retained separately. Current A2 target deployed-code hashes do **not** prove which static source contract produced the deployed bytecode. Production therefore supplies no deployment bindings and leaves address, selector, event and path-edge mapping unresolved. The pure model accepts only a trusted exact deployed-bytecode/source witness for mapping; no contract-name or metadata-stripped heuristic is used. Unknown selectors remain contract-level only if the contract itself is proven. No static graph or Investigation Path changes.

Fixed Phase 10B explanation keys include `observed-call`, `observed-state-change`, `runtime-only-call`, `static-edge-observed`, `static-edge-not-observed`, `reverted-transaction`, `unmapped-runtime-call` and `observed-log`. Phase 10B visual integration is implemented as a read-only presentation of this exact model. The model does not verify a finding, change confidence or severity, infer profit/loss, launch Impact Lab, perform RPC calls or claim live-chain execution.

## Phase 9B static path UI boundary

The Investigation Path page renders the Phase 9A static graph result alongside exact selected Impact Overlay evidence in Static Investigation, Observed Execution and Compare views. The page has no Impact Lab launch action. Phase 10B displays observations only through exact execution and canonical path/function identities while preserving the existing reviewed PoC and verified local session authority. Static paths remain distinct from observed calls and state changes.

## Future Protocol Intelligence path overlay boundary

Phase 9A Investigation Paths are static graph-backed navigation. A later visual overlay may align a reviewed local D1 execution trace and C1 state diff with exact path/function identities where provenance permits. Observed calls and state changes must remain separate records; they cannot rewrite static path truth, verify a finding by themselves, or broaden existing Impact Lab session/review authority. Phase 9A performs no execution.

## Phase D1: local transaction trace capture

After the reviewed Forge worker finishes and its per-job bridge closes, the controller traces only transaction hashes recorded by that bridge for the current execution. Its guarded managed-Anvil capability performs fixed local `eth_getTransactionReceipt`, `eth_getBlockByNumber`, and `debug_traceTransaction` with Anvil 1.7.1 `callTracer`. The PoC worker bridge and browser expose no debug method; the upstream read-only proxy still rejects `debug_*`, `trace_*`, signing and transaction submission. Capture occurs before C1 POST state, diff persistence and final baseline reset.

Versioned traces bind the exact execution, session, runtime token hash, reviewed source, original fork block/hash, target code hashes, and ordered local transaction hash. A separate receipt records its **local execution block** number/hash, transaction index, status and gas used; bounded ordered logs retain address, topics, data prefix/length/hash. A flattened preorder call tree preserves parent/depth, CALL and DELEGATECALL distinctions, exact decimal value, gas facts when present, 4-byte input selector, bounded input/output prefixes with SHA-256 and byte counts, error/revert facts, and exact known-target address matches. Unknown call types remain explicit. Canonical framed hashes and read-time integrity checks protect immutable normalized artifacts.

Limits are four bridge-recorded transactions, 256 nodes and depth 24 per transaction, 64 logs with four topics each, 64 KiB per data field, a 256-byte retained prefix, 128 KiB total log data, 1 MiB RPC response, 512 KiB serialized trace, ten seconds per transaction and 30 seconds per execution. Overflow fails that trace capture; no partial tree is finalized. A trace failure leaves C1 state capture and reset active and records trace status `failed`. Compilation failure has no trace artifact; a completed zero-transaction run has a valid empty finalized trace set. Historical B1/C1 executions remain readable with null trace references. Migration `0013_v0_3_impact_local_traces` stores immutable trace, node and log rows.

The deterministic local A→proxy→B→isolated Forge test captures a benign transaction, nested A→B CALL and DELEGATECALL while upstream A remains unchanged and receives zero transaction or debug/trace methods. A fixture-only local reverted transaction proves Anvil's failed receipt/call shape. The fixed Forge script simulates a reverting call without submitting it, so that reviewed execution correctly has no hash or trace; the fixture-only transaction is not attributed to it. Trace facts and state changes do not establish profit, protocol loss, severity or vulnerability validity. Asset-flow analysis remains a future phase; the read-only Phase 10B visual UI is implemented. The production Compose worker still needs a trusted current-source rebuild and live smoke before v0.3 release; D1 downloads no Foundry/compiler tooling.

## Phase C1: bounded local state capture and diff

C1 adds a controller-owned observation plan to each explicit reviewed PoC run. The default plan captures the disposable sender and target contracts' native balances. A request may add only typed native, ERC-20 `balanceOf`, ERC-721 `ownerOf`, ERC-1155 `balanceOf`, exact storage-slot, and fixed ERC-20 `totalSupply` observations. There is no arbitrary RPC method, calldata, decoder, or whole-chain scan. Limits are 24 native addresses, eight each of ERC-20/721/1155 and fixed view entries, 16 storage slots, and 64 total observations; duplicates and invalid IDs fail before Forge starts.

Execution order is baseline reset → PRE capture → fixed Forge worker → POST capture where execution may have occurred → exact diff and atomic persistence → baseline reset. Compilation failure retains PRE only; a failed POST retains PRE only and still resets. A reverting run may have a finalized zero-change diff. Each read goes through the guarded managed local Anvil session, never a direct upstream client. Reads have per-RPC and 20-second total capture bounds. Available values use decimal integer strings, canonical addresses and exact lowercase hex; failed reads are explicit `unavailable` observations rather than zero. PRE and POST record their own local block number and timestamp.

Versioned plan, snapshot and diff hashes use ordered canonical frames. Immutable normalized rows store observations and changes, with execution, runtime-token hash, reviewed source, exact fork block/hash and target bytecode identities. Reads verify row counts, bindings, hashes and derived changes. Historical B1 executions have null state references and are never backfilled. The read-only execution state API returns bounded artifacts; the execution summary exposes only state availability, change count and IDs. The diff states what the selected observations changed. It does not establish exploitability, severity, asset flow, authoritative evidence, or a hypothesis lifecycle transition. Tracing and asset-flow analysis remain future phases.

The opt-in local integration uses upstream fixture Anvil A → read-only proxy → fork B → fixed networkless Forge worker. A benign reviewed script sends one wei to the target and changes storage slot zero on B. C1 observes the exact +1 wei and slot change before reset, then verifies A was unchanged, zero transaction methods reached the upstream proxy, B returned to baseline, and the persisted state hashes remain stable. ERC token/NFT categories are covered by deterministic capture tests; a real ERC-20 fixture remains for later compatibility hardening. No third-party provider or vulnerability PoC is used.

Production Compose release hardening remains open: an older cached worker tag failed the live loopback bridge smoke, while the newer locally cached test image passed. The Compose worker needs a current-source rebuild and repeat smoke before a production release. C1 did not fetch the Dockerfile's remote Foundry artifact or compiler.

## Phase B1: reviewed manual Forge execution

B1 adds a manual-only PoC workflow. A researcher submits one bounded `ImpactPoC.s.sol` file (at most 16 KiB, strict UTF-8, Solidity 0.8.36, no imports), then explicitly reviews its immutable SHA-256 revision. Creating or reviewing a PoC does not execute it. An explicit execution request contains only the reviewed artifact ID under a verified session route. Edits create a fresh draft requiring review. No model generates or adapts PoCs, and a successful run does not verify a hypothesis, admit authoritative evidence, change severity, or move lifecycle state.

The normal Compose deployment pre-creates a dedicated `impact-poc-worker`. The web service has only a narrow shared Unix socket; neither web nor worker receives the Docker socket. The worker is separate from the networkless verification worker and runs as UID 10003, with network mode `none`, a read-only root, all capabilities dropped, no-new-privileges, seccomp/AppArmor, 48 PIDs, one CPU, 1 GiB memory, bounded tmpfs, and no database, repository, provider secret or wallet mount. Its only persistent read-only mount is the existing trusted compiler cache subdirectory. The browser cannot select an image, command, endpoint, environment, mount, or wallet. The pinned Foundry 1.7.1 build stage supplies Forge; the worker checks its root-owned executable, version and SHA-256. The fixed script mode is `forge script ... --broadcast --unlocked --sender <disposable Anvil account> --rpc-url http://127.0.0.1:18545` after a fixed offline `forge build`. The ephemeral server-owned project disables FFI and filesystem permissions, uses the cached trusted solc 0.8.36, and is removed after each run. No repository Foundry config or wallet environment is inherited.

The worker's loopback RPC talks through a private Unix socket to the web controller. The controller rechecks the current fork runtime token and central managed-Anvil execution guard before forwarding each request. The local allowlist is `eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getCode`, `eth_getBalance`, `eth_getStorageAt`, `eth_call`, `eth_getLogs`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getTransactionCount`, `eth_feeHistory`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_estimateGas`, and `eth_sendTransaction`. Only `eth_sendTransaction` mutates, only with the assigned disposable sender, and at most four attempts per run. `eth_sendRawTransaction`, signing, wallet, `anvil_*`, `hardhat_*` and `evm_*` are not forwarded. Forge 1.7.1 attempts `anvil_nodeInfo` and `eth_getAccountInfo` during setup; the bridge returns a local JSON-RPC method-not-found error and Forge falls back. The upstream proxy remains read-only.

Each execution resets the fork to baseline before the job and again afterward, including failure. The job records source hash, fork runtime-token hash, exact block/hash, target code hashes, Forge identity, bounded output, status and local-only transaction hashes. A global active-job bound and database constraint prevent concurrent execution in one web controller. Server restart marks in-progress records failed; no process is resumed. Cancellation is not exposed in B1; the fixed worker process and time limits bound a running job. State diff, trace and impact interpretation remain Phase C work. The local A→proxy→fork B→networkless worker integration compiled and ran a benign transfer only on B, verified A unchanged and zero upstream transaction methods, blocked FFI, and reset B. No third-party RPC smoke was configured.

**User-facing workflow:** Impact Lab. **Status:** v0.3 Phase B1 implemented and unreleased. Reviewed manual PoC execution is available through internal APIs; result export, CLI and GUI remain future work.

## Phase A3: real fork and isolated probe runtime

The deterministic integration uses two checksum-verified Foundry Anvil 1.7.1 processes. Upstream fixture A has chain ID 31337, two disposable accounts, a tiny non-vulnerable contract whose runtime bytecode reads storage slot zero, and an exact mined block. Fixture-only `anvil_setCode`, `anvil_setStorageAt`, and `anvil_mine` prepare A before the proxy starts; these calls are never sent through the proxy. Fork B receives only the private read-only proxy URL and the exact block number. ContractHunter's normal ready-state proof confirms the same chain, block hash, deployed-code SHA-256, and baseline snapshot. The test confirms storage and `eth_call` return the fixture value, sends one harmless transfer **only to B**, then reverts B's snapshot. A's code, storage and balance remain unchanged. Neither a production provider nor a user wallet participates.

The real fork forwarded only `eth_chainId`, `eth_gasPrice`, `eth_getBalance`, `eth_getBlockByNumber`, `eth_getCode`, `eth_getStorageAt`, and `eth_getTransactionCount`. Anvil also attempted `eth_getAccountInfo`; the proxy rejected it, and Anvil successfully fell back to the allowed reads. No transaction, signing, `personal_*`, `anvil_*`, `hardhat_*`, `wallet_*`, or `evm_*` method was forwarded. The A2 18-method allowlist is unchanged: this one EVM fixture proves the seven observed methods, but cannot prove other historical-block, proof, log, receipt, or fee methods unnecessary for all supported chains and lazy-read paths. The remaining methods are narrowly read-only: `eth_blockNumber` resolves a numeric head; `eth_getBlockByHash` looks up a pinned block; `eth_call` reads contract state; `eth_getLogs` and `eth_getBlockReceipts` read block events/receipts; `eth_getTransactionByHash` and `eth_getTransactionReceipt` read transaction history; `eth_getProof` reads account/storage proof; `eth_feeHistory` and `eth_maxPriorityFeePerGas` read fee estimates; `net_version` reads network identity. The observed seven read chain identity, gas price, balance, block, code, storage, and nonce respectively. Any proposed removal needs a broader chain/lazy-read compatibility test. No mutation method was added.

`ImpactPoCRuntimeService` is a separate internal foundation for Phase B. It accepts only a verified `sessionId`, resolves the current in-memory fork handle, passes the central execution guard, and binds a runtime to the handle token hash. Docker runs a fixed image **ID** with schema label `v1`; the base is digest-pinned. The container has `--network none`, so it has only loopback and no IP route to the host, LAN, proxy, upstream or internet. Its sole mount is one read-only bind of a per-session Unix-domain socket. ContractHunter's host-side bridge rechecks the current token and fork guard on each request and, in A3, permits only six bounded read methods against the assigned fork. There is no network transit through Anvil or proxy, no DNS route, no Docker socket, database, repository store, wallet, provider secret, arbitrary image, command, environment or endpoint input. Each session has a distinct socket; a container for session A has no mount for session B. A fork stop/recreate invalidates the old token and tears down the associated runtime. Startup removes labeled stale probe containers rather than trusting persisted runtime metadata. A3 probe runtime status is memory-only; migration `0010` was the latest at that milestone.

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
