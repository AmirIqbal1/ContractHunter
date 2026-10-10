import { getDatabase, recordImpactForkSession } from "@contracthunter/db";
import { ImpactForkService } from "@contracthunter/scanners";

// Internal engine entry point. No browser route or raw RPC endpoint exists in Phase A1.
export function createImpactForkService(): ImpactForkService {
  const database = getDatabase();
  return new ImpactForkService({ onStatus: (session) => recordImpactForkSession(database, session) });
}
