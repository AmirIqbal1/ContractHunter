# Development

Prerequisites are Node.js 20+, npm, and Git. Docker Compose is recommended. Local verification additionally needs Linux Bubblewrap network/PID namespaces, `prlimit`, Forge, and a trusted compiler cache.

```bash
cp .env.example .env
npm install
npm run dev
```

Local data defaults to `data/` and contains SQLite, cloned repositories, compiler/tool caches, and verification workspaces.

```bash
npm test
npm run lint
npm run typecheck
npm run build
docker compose up --build
docker compose down
```

`.env` must never be committed; `.env.example` may contain safe defaults only.

## Release smoke test

A successful Next.js build is not sufficient to catch every Server/Client runtime boundary issue. Before releases, run the production Docker image and smoke-test `/`, an existing `/hunts/:id`, and an existing `/hypotheses/:id` page where practical. Inspect logs for server-rendering errors. Keep local verification fail-closed when isolation or its toolchain is unavailable.

The project previously hit a production-only Server/Client boundary error when `shouldPollHunt()` was called from a Server Component through a client-marked module. Production-container rendering is therefore part of release validation, not an optional build substitute.
