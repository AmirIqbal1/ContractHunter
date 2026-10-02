import { assessPersistedHypothesisVerificationStrategies, getDatabase, type DatabaseClient } from "@contracthunter/db";
import { NextResponse } from "next/server";
import { idSchema } from "@/lib/api";
import { toPublicVerificationOptions } from "./public-verification-options";

type RouteContext = { params: Promise<{ id: string }> };

/** Read-only capability assessment. No planner, provider, or worker is constructed. */
export async function readVerificationOptions(_request: Request, context: RouteContext, database: DatabaseClient = getDatabase()) {
  const id = idSchema.safeParse((await context.params).id);
  if (!id.success) return NextResponse.json({ error: "Invalid hypothesis identifier." }, { status: 400 });
  const assessment = assessPersistedHypothesisVerificationStrategies(database, id.data);
  if (!assessment) return NextResponse.json({ error: "Hypothesis not found." }, { status: 404 });
  return NextResponse.json({ options: toPublicVerificationOptions(assessment) });
}
