# Changelog

## 0.3.0 — release candidate, not released

### Added

- Protocol Map, Contract and Function Explorers, seven Security Views, Start Here and static Investigation Paths.
- Isolated managed Anvil forks, reviewed manual Forge PoCs, bounded PRE/POST state capture and transaction traces.
- Runtime Impact overlays, deterministic Asset Flow and reviewed per-asset scenario accounting.
- Bounded independent and cumulative replay, immutable Evidence Packages and deterministic bug-bounty Markdown reports with a browser print view.

### Security

- Upstream RPC remains read-only; the PoC worker is networkless and receives only guarded access to its assigned local fork.
- Exact scan bindings protect Impact, scenario, replay, package and report evidence. Legacy Impact ID routes require a scan selector and return projected execution data.
- Export paths reject detected credentials and host paths; downloads use safe ID-based filenames and immutable package/report integrity checks.
- Release hardening rebuilt the production Impact worker from pinned inputs and passed a disposable local-fork smoke with zero upstream mutations.

### Changed

- The product now presents a source-linked Web3 research workflow from static protocol understanding through reviewed local reproduction and evidence export.
- Static investigation facts, observed local effects, manual scenario roles and researcher-authored report text remain separately labelled.

### Known limitations

- Static extraction and deployed-code mapping may be incomplete. Captured state, trace and asset accounting are bounded; ERC20/ERC721 Transfer classification may remain unknown.
- Independent replay results are not cumulative impact. Cumulative replay reports completed local iterations only. Neither mode establishes maximum drain or live-chain exploitability.
- No fiat valuation, inferred severity, automatic bounty eligibility, autonomous exploit generation or formal proof is provided.
- Browser Print provides optional PDF saving; no server PDF engine is included.

## 0.2.2 — released

- Smarter deterministic verification planning, scan-time source snapshots and explicit reviewed plan reuse. Earlier release detail remains in the roadmap.
