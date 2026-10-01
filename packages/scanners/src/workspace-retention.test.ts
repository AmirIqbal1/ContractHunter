import Database from "better-sqlite3";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe("operator workspace retention", () => {
  it("recognizes Echidna and replay workspaces while preserving active, recent, unknown, and symlinked paths", async () => {
    const root = mkdtempSync(path.join(tmpdir(), "ch-retention-")); roots.push(root);
    const workspaces = path.join(root, "workspaces"), databasePath = path.join(root, "history.db"); mkdirSync(workspaces);
    const db = new Database(databasePath);
    db.exec("CREATE TABLE hypothesis_verification_runs (id TEXT, status TEXT, completed_at INTEGER); CREATE TABLE executable_invariant_runs (id TEXT, status TEXT, completed_at INTEGER, engine TEXT); CREATE TABLE invariant_replay_runs (id TEXT, status TEXT, completed_at INTEGER, artifact_id TEXT); CREATE TABLE invariant_replay_artifacts (id TEXT, created_at INTEGER)");
    const old = Date.now() - 30 * 86_400_000, recent = Date.now() - 86_400_000;
    const ids = Object.fromEntries(["echidna", "foundry", "replay", "active", "recent", "unknown", "symlinked"].map((name) => [name, crypto.randomUUID()])) as Record<string, string>;
    const make = (name: string, file: string, manifest: object) => { const directory = path.join(workspaces, ids[name]); mkdirSync(directory); writeFileSync(path.join(directory, file), JSON.stringify(manifest)); return directory; };
    make("echidna", ".contracthunter-echidna.json", { formatVersion: 3, planKind: "executable-invariant", generatedBy: "contracthunter", engine: "echidna", workspaceId: ids.echidna });
    make("foundry", ".contracthunter-invariant.json", { formatVersion: 2, planKind: "executable-invariant", generatedBy: "contracthunter", workspaceId: ids.foundry });
    make("replay", ".contracthunter-replay.json", { formatVersion: 1, planKind: "invariant-replay", generatedBy: "contracthunter", workspaceId: ids.replay });
    make("active", ".contracthunter-echidna.json", { formatVersion: 3, planKind: "executable-invariant", generatedBy: "contracthunter", engine: "echidna", workspaceId: ids.active });
    make("recent", ".contracthunter-echidna.json", { formatVersion: 3, planKind: "executable-invariant", generatedBy: "contracthunter", engine: "echidna", workspaceId: ids.recent });
    make("unknown", ".future-workspace.json", { formatVersion: 4 });
    const symlinked = make("symlinked", ".contracthunter-echidna.json", { formatVersion: 3, planKind: "executable-invariant", generatedBy: "contracthunter", engine: "echidna", workspaceId: ids.symlinked });
    symlinkSync(root, path.join(symlinked, "nested-link"));
    for (const name of ["echidna", "foundry", "active", "recent", "unknown", "symlinked"]) db.prepare("INSERT INTO executable_invariant_runs VALUES (?, ?, ?, ?)").run(ids[name], name === "active" ? "running" : name === "recent" ? "failed" : "completed", name === "recent" ? recent : old, name === "foundry" ? "foundry" : "echidna");
    db.prepare("INSERT INTO invariant_replay_runs VALUES (?, 'completed', ?, ?)").run(ids.replay, old, crypto.randomUUID()); db.close();
    // @ts-expect-error The operator JavaScript module has no TypeScript declaration.
    const retention = await import("../../../scripts/workspace-retention.mjs");
    const config = { root: workspaces, database: databasePath, completedDays: 7, failedDays: 14, apply: false };
    const dry = await retention.inspectWorkspaceRetention(config); expect(dry.items.filter((item: { decision: string }) => item.decision === "delete").map((item: { id: string }) => item.id).sort()).toEqual([ids.echidna, ids.foundry, ids.replay].sort());
    expect(existsSync(path.join(workspaces, ids.echidna))).toBe(true);
    const applied = await retention.inspectWorkspaceRetention({ ...config, apply: true }); expect((await retention.applyWorkspaceRetention(applied)).sort()).toEqual([ids.echidna, ids.foundry, ids.replay].sort());
    for (const name of ["active", "recent", "unknown", "symlinked"]) expect(existsSync(path.join(workspaces, ids[name]))).toBe(true);
    const history = new Database(databasePath, { readonly: true }); expect(history.prepare("SELECT count(*) AS count FROM executable_invariant_runs").get()).toEqual({ count: 6 }); history.close();
  });
});
