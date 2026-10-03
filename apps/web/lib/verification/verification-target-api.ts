import { NextResponse } from "next/server";
import { getDatabase, type DatabaseClient } from "@contracthunter/db";
import { idSchema } from "@/lib/api";
import { discoverVerificationTarget } from "./verification-target-discovery";

type RouteContext = { params: Promise<{ id: string }> };

/** Read-only fresh assessment. Browser-supplied target/candidate fields have no authority. */
export async function readVerificationTarget(request: Request, context: RouteContext, database: DatabaseClient = getDatabase()) {
  const id = idSchema.safeParse((await context.params).id);
  if (!id.success) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  if (new URL(request.url).search) return NextResponse.json({ error: "Verification target queries do not accept client fields." }, { status: 400 });
  const target = discoverVerificationTarget(database, id.data);
  if (!target) return NextResponse.json({ error: "Hypothesis not found." }, { status: 404 });
  return NextResponse.json({ target });
}
