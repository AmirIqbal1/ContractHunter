# Architecture

```text
apps/web          Next.js UI, API routes, scanning runner, verification planner/interpreter
packages/core     Domain models, Zod schemas, configuration, safety rules
packages/db       Drizzle schema and SQLite repository functions
packages/scanners Dependency/compiler managers, scanners, parsers, workspace builder, worker protocol
docker/verification-worker.ts  Networkless deterministic Forge controller
data volume       SQLite, cloned repositories, trusted compiler cache
verification-workspaces volume  Generated harnesses only
verification-ipc volume         Group-restricted Unix socket only
```

The application is a TypeScript monorepo. SQLite/Drizzle stores scans, findings, investigations, AI records, hypotheses, and verification history. Cloned repositories live below `REPOSITORY_DIR`; persistent data is below `DATA_DIR`. Docker provides the production runtime and persistent data volume.

```text
UI/API → runner → repository preparation → compiler resolution
                 → Slither → Aderyn → correlation → completed static scan
                 → optional AI analysis → optional specialist review
                 → hypotheses → optional plan → explicit local verification
```

The scanning runner is intentionally small and single-instance; interrupted jobs are marked failed after restart. Static scanning is completed before optional AI stages. For verification, the web service validates persisted evidence, copies an allowlisted source closure, generates a deterministic Foundry harness/configuration, validates hashes, and sends bounded identifiers to the worker over a Unix-domain socket. The worker revalidates the workspace and trusted compiler, then executes fixed Forge arguments under `prlimit` without networking. It returns execution facts only. The web interpreter creates dynamic evidence and applies the hypothesis lifecycle rules. There is no Docker socket, dynamic container creation, or nested Bubblewrap execution.
