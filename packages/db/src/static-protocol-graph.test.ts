import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { REPOSITORY_MAP_SCHEMA, REPOSITORY_MAPPER_RULESET, repositoryClasses, repositoryMapId,
  repositorySourceUniverseHash, STATIC_GRAPH_EXTRACTOR_VERSION, STATIC_PROTOCOL_GRAPH_SCHEMA,
  PROTOCOL_GRAPH_SCHEMA, protocolGraphId, staticProtocolGraphContentHash,
  type RepositoryMap, type StaticProtocolGraphArtifact } from "@contracthunter/core";
import { closeDatabase, createDatabase, createScan, finalizeRepositoryMap,
  finalizeStaticProtocolGraph, readStaticProtocolGraph } from "./index";

const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
function setup() {
  const directory = mkdtempSync(path.join(tmpdir(), "ch-static-graph-db-")); directories.push(directory);
  const db = createDatabase(path.join(directory, "test.db"));
  const scan = createScan(db, { repositoryUrl: "https://example.invalid/project", repositoryName: "project", depth: "quick" });
  const commit = "a".repeat(40);
  db.sqlite.prepare("UPDATE scans SET resolved_commit=? WHERE id=?").run(commit, scan.id);
  const sourceUniverseHash = repositorySourceUniverseHash([]);
  const map: RepositoryMap = { schema: REPOSITORY_MAP_SCHEMA, id: repositoryMapId(scan.id, commit, sourceUniverseHash),
    scanId: scan.id, resolvedCommit: commit, ruleset: REPOSITORY_MAPPER_RULESET, sourceUniverseHash,
    roots: [], files: [], summary: { solidityFiles: 0, contracts: 0,
      classes: Object.fromEntries(repositoryClasses.map((kind) => [kind, 0])) as RepositoryMap["summary"]["classes"], directories: [] }, warnings: [] };
  const extractorVersion = `${STATIC_GRAPH_EXTRACTOR_VERSION}:${map.id}`;
  const producers = [{ origin: "repository-mapper" as const, version: REPOSITORY_MAPPER_RULESET },
    { origin: "contracthunter-parser" as const, version: STATIC_GRAPH_EXTRACTOR_VERSION }];
  const graph: StaticProtocolGraphArtifact["graph"] = { schema: PROTOCOL_GRAPH_SCHEMA,
    id: protocolGraphId(scan.id, commit, extractorVersion, producers), scanId: scan.id, resolvedCommit: commit,
    extractorVersion, producers, sourceUnits: [], nodes: [], edges: [], classifications: [], warnings: [] };
  const content = { schema: STATIC_PROTOCOL_GRAPH_SCHEMA, repositoryMapId: map.id, graph,
    functionFacts: [], findingLinks: [], unresolved: [], summary: { contracts: 0, interfaces: 0, libraries: 0,
      functions: 0, edges: 0, externalCalls: 0, entryPoints: 0, proxies: 0, delegatecalls: 0,
      findingsLinkedNodes: 0, unresolvedRelationships: 0 } };
  const artifact: StaticProtocolGraphArtifact = { ...content, contentSha256: staticProtocolGraphContentHash(content) };
  return { db, scan, map, artifact };
}

describe("static ProtocolGraph persistence", () => {
  it("stores an immutable scan/map-bound graph; historical scans remain empty", () => {
    const { db, scan, map, artifact } = setup();
    expect(readStaticProtocolGraph(db, scan.id)).toBeNull();
    finalizeRepositoryMap(db, map);
    finalizeStaticProtocolGraph(db, artifact);
    expect(readStaticProtocolGraph(db, scan.id)).toEqual(artifact);
    expect(() => finalizeStaticProtocolGraph(db, artifact)).toThrow();
    expect(() => db.sqlite.prepare("UPDATE static_protocol_graphs SET schema='other' WHERE id=?").run(artifact.graph.id)).toThrow();
    expect(() => db.sqlite.prepare("DELETE FROM static_protocol_graphs WHERE id=?").run(artifact.graph.id)).toThrow();
    expect(db.sqlite.pragma("foreign_key_check")).toEqual([]);
    closeDatabase(db);
  });
  it("rejects wrong map binding and tampered stored content", () => {
    const { db, scan, map, artifact } = setup();
    finalizeRepositoryMap(db, map);
    expect(() => finalizeStaticProtocolGraph(db, { ...artifact, repositoryMapId: `rm:${"f".repeat(64)}` })).toThrow();
    finalizeStaticProtocolGraph(db, artifact);
    db.sqlite.exec("DROP TRIGGER static_protocol_graphs_immutable");
    db.sqlite.prepare("UPDATE static_protocol_graphs SET artifact_json=? WHERE id=?").run("{}", artifact.graph.id);
    expect(() => readStaticProtocolGraph(db, scan.id)).toThrow("static_graph_storage_integrity_invalid");
    expect(readStaticProtocolGraph(db, randomUUID())).toBeNull();
    closeDatabase(db);
  });
});
