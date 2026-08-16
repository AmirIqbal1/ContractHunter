import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { shouldPollHunt } from "@/lib/hunt-polling";

describe("hunt polling state", () => {
  it.each([
    ["completed", "pending", "disabled"],
    ["completed", "running", "disabled"],
    ["completed", "completed", "pending"],
    ["completed", "completed", "running"],
  ] as const)("polls for scan=%s ai=%s review=%s", (status, aiStatus, reviewStatus) => {
    expect(shouldPollHunt(status, aiStatus, reviewStatus)).toBe(true);
  });

  it.each([
    ["completed", "completed", "completed"],
    ["completed", "failed", "failed"],
    ["failed", "failed", "failed"],
  ] as const)("stops after terminal scan=%s ai=%s review=%s", (status, aiStatus, reviewStatus) => {
    expect(shouldPollHunt(status, aiStatus, reviewStatus)).toBe(false);
  });

  it("continues polling while the static scan is active", () => {
    expect(shouldPollHunt("scanning", "disabled", "disabled")).toBe(true);
  });

  it("keeps the predicate server-safe", () => {
    expect(readFileSync(new URL("../lib/hunt-polling.ts", import.meta.url), "utf8")).not.toContain('"use client"');
  });
});
