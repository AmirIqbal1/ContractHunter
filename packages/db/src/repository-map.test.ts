import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { REPOSITORY_MAP_SCHEMA, REPOSITORY_MAPPER_RULESET, repositoryClasses, repositoryMapId, repositorySourceUniverseHash, type RepositoryMap } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, finalizeRepositoryMap, readRepositoryMap } from "./index";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
function setup() {
  const directory = mkdtempSync(path.join(tmpdir(), "ch-repository-map-db-")); directories.push(directory);
  const db = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(db, { repositoryUrl: "https://example.invalid/project", repositoryName: "project", depth: "quick" });
  const commit = "a".repeat(40);
  db.sqlite.prepare("UPDATE scans SET resolved_commit=? WHERE id=?").run(commit, scan.id);
  const sourceUniverseHash = repositorySourceUniverseHash([]);
  const map: RepositoryMap = { schema: REPOSITORY_MAP_SCHEMA, id: repositoryMapId(scan.id, commit, sourceUniverseHash),
    scanId: scan.id, resolvedCommit: commit, ruleset: REPOSITORY_MAPPER_RULESET, sourceUniverseHash,
    roots: [], files: [], summary: { solidityFiles: 0, contracts: 0,
      classes: Object.fromEntries(repositoryClasses.map((kind) => [kind, 0])) as RepositoryMap["summary"]["classes"], directories: [] }, warnings: [] };
  return { db, scan, map };
}
describe("Repository Map persistence", () => {
  it("migrates additively, finalizes immutable scan-bound map, and leaves historical scans empty", () => {
    const { db, scan, map } = setup();
    expect(readRepositoryMap(db, scan.id)).toBeNull();
    finalizeRepositoryMap(db, map);
    expect(readRepositoryMap(db, scan.id)).toEqual(map);
    expect(() => finalizeRepositoryMap(db, map)).toThrow();
    expect(() => db.sqlite.prepare("UPDATE repository_maps SET ruleset='other' WHERE id=?").run(map.id)).toThrow();
    expect(() => db.sqlite.prepare("DELETE FROM repository_maps WHERE id=?").run(map.id)).toThrow();
    expect(db.sqlite.pragma("foreign_key_check")).toEqual([]);
    closeDatabase(db);
  });
  it("rejects tampered content and wrong scan identity", () => {
    const { db, scan, map } = setup();
    expect(() => finalizeRepositoryMap(db, { ...map, scanId: randomUUID() })).toThrow();
    finalizeRepositoryMap(db, map);
    db.sqlite.exec("DROP TRIGGER repository_maps_immutable");
    db.sqlite.prepare("UPDATE repository_maps SET map_json=? WHERE id=?").run("{}", map.id);
    expect(() => readRepositoryMap(db, scan.id)).toThrow("repository_map_content_integrity_invalid");
    closeDatabase(db);
  });
});
