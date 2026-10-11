import { NextResponse } from "next/server";
import { configuredImpactRpcs } from "@/lib/impact-lab";

export const runtime = "nodejs";
export async function GET() {
  try { return NextResponse.json({ rpcConfigurations: configuredImpactRpcs().filter((config) => config.enabled).map(({ id, chainId, network }) => ({ id, chainId, network })) }); }
  catch { return NextResponse.json({ error: "Impact Lab configuration unavailable." }, { status: 500 }); }
}
