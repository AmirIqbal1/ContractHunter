import { deriveAssetFlow, type AssetFlow } from "@contracthunter/core";
import { readImpactForkSession, type DatabaseClient } from "@contracthunter/db";
import { loadImpactOverlay } from "./impact-overlay-server";

/** Reuses the exact scan/execution/subject/C1/D1 binding and never reads an RPC. */
export function loadAssetFlow(database: DatabaseClient, scanId: string, executionId: string): AssetFlow | null {
  const overlay = loadImpactOverlay(database, scanId, executionId);
  if (!overlay) return null;
  const session = readImpactForkSession(database, overlay.sessionId);
  if (!session || session.id !== overlay.sessionId) throw Error("asset_flow_session_unavailable");
  return deriveAssetFlow(overlay, { disposableAccounts: session.disposableAccounts,
    trustedAssetStandards: [] });
}
