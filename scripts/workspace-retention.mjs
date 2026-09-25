#!/usr/bin/env node
import Database from "better-sqlite3";
import { lstat, readdir, realpath, rm } from "node:fs/promises";
import path from "node:path";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function options(argv) {
  const value = (name) => { const index = argv.indexOf(name); return index === -1 ? undefined : argv[index + 1]; };
  const number = (name, fallback) => { const parsed = Number(value(name) ?? fallback); if (!Number.isInteger(parsed) || parsed < 1 || parsed > 3650) throw new Error(`${name} must be an integer from 1 to 3650.`); return parsed; };
  if (argv.includes("--help")) return { help: true };
  const root = value("--root") ?? process.env.VERIFICATION_ROOT;
  const database = value("--database") ?? process.env.DATABASE_PATH;
  if (!root || !database) throw new Error("Provide --root and --database (or VERIFICATION_ROOT and DATABASE_PATH).");
  return { help: false, root: path.resolve(root), database: path.resolve(database), completedDays: number("--completed-days", 7), failedDays: number("--failed-days", 14), apply: argv.includes("--apply") };
}

function recordFor(database, id) {
  const verification = database.prepare("SELECT status, completed_at AS completedAt FROM hypothesis_verification_runs WHERE id=?").get(id);
  if (verification) return { kind: "structured-verification", status: verification.status, timestamp: verification.completedAt };
  const invariant = database.prepare("SELECT status, completed_at AS completedAt FROM executable_invariant_runs WHERE id=?").get(id);
  if (invariant) return { kind: "invariant-run", status: invariant.status, timestamp: invariant.completedAt };
  const replay = database.prepare("SELECT status, completed_at AS completedAt FROM invariant_replay_runs WHERE id=?").get(id);
  if (replay) return { kind: "replay-run", status: replay.status, timestamp: replay.completedAt };
  const artifact = database.prepare("SELECT created_at AS createdAt FROM invariant_replay_artifacts WHERE id=?").get(id);
  if (artifact) {
    const active = database.prepare("SELECT 1 FROM invariant_replay_runs WHERE artifact_id=? AND status IN ('queued','running') LIMIT 1").get(id);
    return { kind: "replay-artifact", status: active ? "active" : "completed", timestamp: artifact.createdAt };
  }
  return null;
}

export async function inspectWorkspaceRetention(config, now = Date.now()) {
  const root = await realpath(config.root), info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Verification root must be a real directory.");
  const database = new Database(config.database, { readonly: true, fileMustExist: true });
  try {
    const items = [];
    for (const entry of await readdir(root, { withFileTypes: true })) {
      if (!UUID.test(entry.name) || !entry.isDirectory()) continue;
      const absolute = path.join(root, entry.name), entryInfo = await lstat(absolute);
      if (entryInfo.isSymbolicLink() || await realpath(absolute) !== absolute) continue;
      const record = recordFor(database, entry.name);
      if (!record) { items.push({ id: entry.name, kind: "unknown", decision: "keep", reason: "no matching immutable database history" }); continue; }
      if (["queued", "running", "active"].includes(record.status)) { items.push({ id: entry.name, kind: record.kind, decision: "keep", reason: "active workspace" }); continue; }
      if (typeof record.timestamp !== "number") { items.push({ id: entry.name, kind: record.kind, decision: "keep", reason: "terminal timestamp unavailable" }); continue; }
      const retentionDays = ["failed", "refused"].includes(record.status) ? config.failedDays : config.completedDays;
      const ageMs = now - record.timestamp, eligible = ageMs >= retentionDays * 86_400_000;
      items.push({ id: entry.name, kind: record.kind, status: record.status, ageDays: Math.floor(Math.max(0, ageMs) / 86_400_000), decision: eligible ? "delete" : "keep", reason: eligible ? `older than ${retentionDays}-day retention` : `within ${retentionDays}-day retention` });
    }
    return { root, database: config.database, mode: config.apply ? "apply" : "dry-run", completedDays: config.completedDays, failedDays: config.failedDays, items };
  } finally { database.close(); }
}

export async function applyWorkspaceRetention(report) {
  for (const item of report.items.filter((candidate) => candidate.decision === "delete")) await rm(path.join(report.root, item.id), { recursive: true, force: false });
  return report.items.filter((item) => item.decision === "delete").map((item) => item.id);
}

const invoked = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (invoked) {
  try {
    const config = options(process.argv.slice(2));
    if (config.help) process.stdout.write("Usage: node scripts/workspace-retention.mjs --root PATH --database PATH [--completed-days 7] [--failed-days 14] [--apply]\nDefault mode is read-only dry-run. --apply deletes only eligible UUID workspaces backed by terminal database history.\n");
    else {
      const report = await inspectWorkspaceRetention(config);
      if (config.apply) report.deleted = await applyWorkspaceRetention(report);
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    }
  } catch (error) { process.stderr.write(`Workspace retention failed: ${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; }
}
