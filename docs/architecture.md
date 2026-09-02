# Architecture

```text
apps/web          Next.js UI, API routes, and in-process runner
packages/core     Domain models, Zod schemas, configuration, safety rules
packages/db       Drizzle schema and SQLite repository functions
packages/scanners Dependency/compiler managers, scanners, parsers, verification
data              SQLite, cloned repositories, tool cache, verification workspaces
```

The application is a TypeScript monorepo. SQLite/Drizzle stores scans, findings, investigations, AI records, hypotheses, and verification history. Cloned repositories live below `REPOSITORY_DIR`; persistent data is below `DATA_DIR`. Docker provides the production runtime and persistent data volume.

```text
UI/API → runner → repository preparation → compiler resolution
                 → Slither → Aderyn → correlation → completed static scan
                 → optional AI analysis → optional specialist review
                 → hypotheses → optional plan → explicit local verification
```

The runner is intentionally small and single-instance; interrupted jobs are marked failed after restart. Static scanning is always completed before optional AI stages. Verification is separate: ContractHunter validates persisted evidence, copies an allowlisted source closure, generates a deterministic Foundry harness/configuration, validates hashes, and invokes fixed Forge arguments through isolation.
