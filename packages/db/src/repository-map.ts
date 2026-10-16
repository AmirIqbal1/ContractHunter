import { createHash } from "node:crypto";
import { REPOSITORY_MAP_LIMITS, validateRepositoryMap, type RepositoryMap } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

export function finalizeRepositoryMap(database: DatabaseClient, input: RepositoryMap): void {
  const map = validateRepositoryMap(input);
  const scan = database.sqlite.prepare("SELECT resolved_commit AS resolvedCommit FROM scans WHERE id=?").get(map.scanId) as { resolvedCommit: string | null } | undefined;
  if (!scan || scan.resolvedCommit !== map.resolvedCommit) throw Error("repository_map_scan_identity_invalid");
  const json = JSON.stringify(map);
  if (Buffer.byteLength(json) > REPOSITORY_MAP_LIMITS.metadataBytes) throw Error("repository_map_bounds_exceeded");
  const contentHash = createHash("sha256").update(json).digest("hex");
  database.sqlite.prepare(`INSERT INTO repository_maps
    (id,scan_id,schema,ruleset,resolved_commit,source_universe_hash,content_sha256,map_json,finalized_at)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(map.id, map.scanId, map.schema, map.ruleset, map.resolvedCommit,
    map.sourceUniverseHash, contentHash, json, Date.now());
}

export function readRepositoryMap(database: DatabaseClient, scanId: string): RepositoryMap | null {
  const row = database.sqlite.prepare(`SELECT id,schema,ruleset,resolved_commit AS resolvedCommit,
    source_universe_hash AS sourceUniverseHash,content_sha256 AS contentSha256,map_json AS mapJson
    FROM repository_maps WHERE scan_id=? ORDER BY finalized_at DESC,id DESC LIMIT 1`).get(scanId) as {
    id: string; schema: string; ruleset: string; resolvedCommit: string; sourceUniverseHash: string;
    contentSha256: string; mapJson: string;
  } | undefined;
  if (!row) return null;
  if (Buffer.byteLength(row.mapJson) > REPOSITORY_MAP_LIMITS.metadataBytes ||
    createHash("sha256").update(row.mapJson).digest("hex") !== row.contentSha256) throw Error("repository_map_content_integrity_invalid");
  const map = validateRepositoryMap(JSON.parse(row.mapJson));
  if (map.id !== row.id || map.schema !== row.schema || map.ruleset !== row.ruleset ||
    map.resolvedCommit !== row.resolvedCommit || map.sourceUniverseHash !== row.sourceUniverseHash || map.scanId !== scanId)
    throw Error("repository_map_row_integrity_invalid");
  return map;
}
