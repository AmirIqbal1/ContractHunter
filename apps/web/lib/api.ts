import { NextResponse } from "next/server";
import { z } from "zod";

export const idSchema = z.string().uuid();

export function apiError(error: unknown, fallback = "Request failed.") {
  const message = error instanceof z.ZodError ? "Invalid request." : error instanceof Error ? error.message : fallback;
  return NextResponse.json({ error: message.slice(0, 500) }, { status: error instanceof z.ZodError ? 400 : 500 });
}
