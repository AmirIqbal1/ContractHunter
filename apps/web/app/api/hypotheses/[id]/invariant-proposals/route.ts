import { generateInvariantProposal, readInvariantHistory } from "@/lib/verification/invariant-api";
export const GET = readInvariantHistory;
export const POST = generateInvariantProposal;
