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

Use `docker compose exec -T verification-worker` to inspect `id`, `/proc/self/status`, `/proc/self/attr/current`, `/proc/net/route`, `/proc/net/ipv6_route`, `/sys/class/net`, and `/sys/fs/cgroup/pids.max`. The worker should have only `lo`, no usable default route, zero effective/bounding capabilities, `NoNewPrivs: 1`, `Seccomp: 2`, enforcing AppArmor, and a PID limit of 64. The socket should be mode 0660. The worker should not see `/data/contracthunter.db`, `/data/repositories`, `/var/run/docker.sock`, OpenAI/GitHub secrets, or proxy keys.

A Docker run is also the release smoke test for production-only Next.js behavior. Check `/`, an existing hunt page, an existing hypothesis page, and a saved-plan verification where practical. `.env` must not be committed.
