# Development

Prerequisites are Node.js 20+, npm, Docker, and Docker Compose. The web service uses UID/GID 10001:10001. The separate verification worker uses UID/GID 10002:10001. Docker's default enforcing seccomp and AppArmor profiles are used; there is no custom host profile to install.

```bash
cp .env.example .env
npm install
npm run dev
npm run typecheck
npm test
npm run lint
npm run build
docker compose config
docker compose build
docker compose up -d
docker compose ps
```

Local development without the Compose worker can scan and plan; “Verify locally” fails closed with `verification_worker_unavailable`. Production verification requires the worker's isolated container, the dedicated workspace and IPC named volumes, and a compiler already prepared in `contracthunter-data/tool-home`. Compose mounts only that subpath into the worker as read-only. If the Docker engine cannot mount named-volume subpaths, do not replace it with a whole `/data` mount.

The `contracthunter-data` volume holds the database, repository clones, and trusted compiler cache. Keep it when rebuilding or restarting. On a fresh install, the one-shot `contracthunter-data-init` service prepares `/data/tool-home` as UID/GID `10001:10001` before the worker starts. Compose may create the worker container first and leave an empty root-owned subpath; the initializer safely replaces only that empty, unwritable directory. A populated cache is never replaced. No manual directory creation, ownership change, compiler install, or host AppArmor setup is needed to start the stack. The worker can start with an empty compiler cache; later scans prepare trusted compilers through the web service.

The `verification-workspaces` volume stores generated harness workspaces, while `verification-ipc` stores only the worker socket. Neither contains the main database. Old verification history and plans remain in SQLite and are reusable; generating another AI plan is unnecessary for a rerun.

Schema upgrades are explicit and transactional. `schema_migrations` records `0001_v0_2_0_release_schema`; an existing v0.1.9 database receives additive tables/columns/indexes in one transaction, followed by SQLite quick-integrity, foreign-key and required-table checks. Migration does not rewrite scan, hypothesis or verification statuses and never reconciles failed/active history by deletion or mutation. A migration/index conflict aborts startup and rolls back the migration. Release testing must use an SQLite backup/copy, never the user's live database.

Every invariant retry uses a new run ID and workspace. Every replay retry regenerates source closure, harness, configuration and manifest from the persisted plan/replay identity into a new replay-run workspace; the normalized artifact fingerprint, harness hash, replay-plan hash and counterexample hash must still match before execution. Existing proposal, run, artifact and replay-attempt history is never overwritten.

Workspace cleanup is operator-invoked and dry-run by default:

```bash
npm run workspace:retention -- --root /path/to/verifications --database /path/to/contracthunter.db
npm run workspace:retention -- --root /path/to/verifications --database /path/to/contracthunter.db --apply
```

The default policy keeps completed workspaces for 7 days and failed/refused workspaces for 14 days; both windows are configurable from 1–3650 days. It considers only immediate UUID directories with matching immutable database history. Queued/running workspaces, replay artifacts with an active replay, unknown directories, symlinks and records without a terminal timestamp are always kept. `--apply` removes only entries listed as eligible by the same pass. Database evidence/history and canonical hashes are never removed. There is no automatic cleanup during v0.2.0.

Use `docker compose exec -T verification-worker` to inspect `id`, `/proc/self/status`, `/proc/self/attr/current`, `/proc/net/route`, `/proc/net/ipv6_route`, `/sys/class/net`, and `/sys/fs/cgroup/pids.max`. The worker should have only `lo`, no usable default route, zero effective/bounding capabilities, `NoNewPrivs: 1`, `Seccomp: 2`, enforcing AppArmor, and a PID limit of 64. The socket should be mode 0660. The worker should not see `/data/contracthunter.db`, `/data/repositories`, `/var/run/docker.sock`, OpenAI/GitHub secrets, or proxy keys.

A Docker run is also the release smoke test for production-only Next.js behavior. Check `/`, an existing hunt page, an existing hypothesis page, and a saved-plan verification where practical. `.env` must not be committed.
