import { readStaticProtocolGraph, type DatabaseClient } from "@contracthunter/db";

export function loadProtocolMapForPage(database: DatabaseClient, scanId: string,
  read: typeof readStaticProtocolGraph = readStaticProtocolGraph) {
  try { return { artifact: read(database, scanId), invalid: false }; }
  catch { return { artifact: null, invalid: true }; }
}
