# ContractHunter v0.3.0 — Protocol Intelligence + Impact Lab

**Release candidate notes. v0.3.0 has not been released.**

Protocol Intelligence adds a source-linked Protocol Map, Contract and Function Explorers, deterministic Security Views, Start Here guidance and static Investigation Paths. Exact graph and source identities keep those views navigable without turning audit interest into vulnerability likelihood.

Impact Lab adds isolated local Anvil forks and reviewed manual Forge PoCs. Selected PRE/POST state diffs and bounded transaction traces feed separate runtime overlays and an Asset Flow view. Researchers can review scenario roles, run bounded independent or cumulative local replay, freeze an Evidence Package, and write a deterministic bug-bounty report with Markdown download and browser print view.

The upstream chain supplies read-only state. All PoC transactions target the managed local fork through the isolated worker. Evidence Packages and reports are read-only exports and do not rerun execution. Static paths do not prove exploitability; manual roles do not establish attacker or victim identity. Asset accounting can be partial, and replay makes no claim about maximum impact. The report does not infer severity, fiat value or bounty eligibility. Optional AI analysis remains separate from deterministic evidence and report generation.

Release hardening must finish all final validation and operational gates before the version is bumped or a manual release is performed. The production Impact worker trusted rebuild and disposable local-fork smoke passed in the current hardening run; final candidate validation is recorded separately.
