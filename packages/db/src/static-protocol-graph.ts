import { createHash } from "node:crypto";
import { validateStaticProtocolGraphArtifact, type StaticProtocolGraphArtifact } from "@contracthunter/core";
import type { DatabaseClient } from "./index";

const MAX_BYTES = 33_554_432;
export function finalizeStaticProtocolGraph(database: DatabaseClient, input: StaticProtocolGraphArtifact): void {
  const artifact = validateStaticProtocolGraphArtifact(input);
  const scan = database.sqlite.prepare("SELECT resolved_commit AS resolvedCommit FROM scans WHERE id=?")
    .get(artifact.graph.scanId) as { resolvedCommit: string | null } | undefined;
  const map = database.sqlite.prepare("SELECT scan_id AS scanId,resolved_commit AS resolvedCommit FROM repository_maps WHERE id=?")
    .get(artifact.repositoryMapId) as { scanId: string; resolvedCommit: string } | undefined;
  if (!scan || !map || scan.resolvedCommit !== artifact.graph.resolvedCommit ||
    map.scanId !== artifact.graph.scanId || map.resolvedCommit !== artifact.graph.resolvedCommit)
    throw Error("static_graph_scan_map_identity_invalid");
  const json = JSON.stringify(artifact);
  if (Buffer.byteLength(json) > MAX_BYTES) throw Error("static_graph_storage_limit_exceeded");
  database.sqlite.prepare(`INSERT INTO static_protocol_graphs
    (id,scan_id,repository_map_id,schema,graph_schema,extractor_version,resolved_commit,
      content_sha256,storage_sha256,artifact_json,finalized_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    artifact.graph.id, artifact.graph.scanId, artifact.repositoryMapId, artifact.schema, artifact.graph.schema,
    artifact.graph.extractorVersion, artifact.graph.resolvedCommit, artifact.contentSha256,
    createHash("sha256").update(json).digest("hex"), json, Date.now());
}

export function readStaticProtocolGraph(database: DatabaseClient, scanId: string): StaticProtocolGraphArtifact | null {
  const row = database.sqlite.prepare(`SELECT id,repository_map_id AS repositoryMapId,schema,graph_schema AS graphSchema,
    extractor_version AS extractorVersion,resolved_commit AS resolvedCommit,
    content_sha256 AS contentSha256,storage_sha256 AS storageSha256,artifact_json AS artifactJson
    FROM static_protocol_graphs WHERE scan_id=? ORDER BY finalized_at DESC,id DESC LIMIT 1`).get(scanId) as {
      id: string; repositoryMapId: string; schema: string; graphSchema: string; extractorVersion: string;
      resolvedCommit: string; contentSha256: string; storageSha256: string; artifactJson: string;
    } | undefined;
  if (!row) return null;
  if (Buffer.byteLength(row.artifactJson) > MAX_BYTES ||
    createHash("sha256").update(row.artifactJson).digest("hex") !== row.storageSha256)
    throw Error("static_graph_storage_integrity_invalid");
  const artifact = validateStaticProtocolGraphArtifact(JSON.parse(row.artifactJson));
  if (artifact.graph.id !== row.id || artifact.repositoryMapId !== row.repositoryMapId ||
    artifact.schema !== row.schema || artifact.graph.schema !== row.graphSchema ||
    artifact.graph.extractorVersion !== row.extractorVersion || artifact.graph.resolvedCommit !== row.resolvedCommit ||
    artifact.contentSha256 !== row.contentSha256 || artifact.graph.scanId !== scanId)
    throw Error("static_graph_row_integrity_invalid");
  return artifact;
}
