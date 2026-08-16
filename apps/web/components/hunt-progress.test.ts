import { afterEach, describe, expect, it, vi } from "vitest";
import {
  allScannersTerminal,
  currentStageLabel,
  elapsedMilliseconds,
  formatElapsed,
  hasStalledCondition,
  shouldShowStalledWarning,
  type HuntProgressState,
} from "./hunt-progress";

const scanning = (overrides: Partial<HuntProgressState> = {}): HuntProgressState => ({
  status: "scanning",
  aiStatus: "disabled",
  reviewStatus: "disabled",
  scannerStatuses: ["completed", "failed"],
  ...overrides,
});

afterEach(() => vi.useRealTimers());

describe("hunt progress", () => {
  it("calculates and formats an active timer from startedAt, falling back to createdAt", () => {
    expect(elapsedMilliseconds("2026-08-16T10:00:00.000Z", "2026-08-16T09:59:00.000Z", null, Date.parse("2026-08-16T10:01:42.900Z"))).toBe(102_900);
    expect(elapsedMilliseconds(null, "2026-08-16T10:00:00.000Z", null, Date.parse("2026-08-16T10:12:08.000Z"))).toBe(728_000);
    expect(formatElapsed(102_900)).toBe("01:42");
    expect(formatElapsed(728_000)).toBe("12m 08s");
  });

  it("calculates a terminal timer from completedAt instead of the current time", () => {
    expect(elapsedMilliseconds("2026-08-16T10:00:00.000Z", "2026-08-16T09:59:00.000Z", "2026-08-16T10:03:05.000Z", Date.parse("2026-08-16T11:00:00.000Z"))).toBe(185_000);
  });

  it.each([
    ["queued", "Queued"],
    ["cloning", "Cloning repository"],
    ["detecting", "Detecting project"],
    ["preparing_dependencies", "Preparing dependencies"],
    ["preparing_compiler", "Preparing compiler"],
    ["completed", "Static scan complete"],
    ["failed", "Failed"],
  ] as const)("labels %s as %s", (status, label) => {
    expect(currentStageLabel(scanning({ status }))).toBe(label);
  });

  it("uses scanner and AI state for precise scanning labels", () => {
    expect(currentStageLabel(scanning({ scannerStatuses: ["running", "pending"] }))).toBe("Running security scanners");
    expect(currentStageLabel(scanning())).toBe("Preparing AI analysis");
    expect(currentStageLabel(scanning({ aiStatus: "running" }))).toBe("Running AI protocol analysis");
    expect(currentStageLabel(scanning({ aiStatus: "completed", reviewStatus: "running" }))).toBe("Running AI security review");
  });

  it("recognises all configured scanners terminal with AI waiting", () => {
    expect(allScannersTerminal(["completed", "failed", "unavailable"])).toBe(true);
    expect(hasStalledCondition(scanning())).toBe(true);
  });

  it("shows the stalled warning only after 30 continuous seconds", () => {
    vi.useFakeTimers();
    vi.setSystemTime("2026-08-16T10:00:00.000Z");
    const observedAt = Date.now();
    vi.advanceTimersByTime(29_999);
    expect(shouldShowStalledWarning(observedAt, Date.now())).toBe(false);
    vi.advanceTimersByTime(1);
    expect(shouldShowStalledWarning(observedAt, Date.now())).toBe(true);
  });

  it("does not flag a stall while any scanner is running", () => {
    expect(hasStalledCondition(scanning({ scannerStatuses: ["completed", "running"] }))).toBe(false);
  });

  it("does not flag a stall while AI is running", () => {
    expect(hasStalledCondition(scanning({ aiStatus: "running" }))).toBe(false);
  });

  it("does not flag a stall after completion or failure", () => {
    expect(hasStalledCondition(scanning({ status: "completed" }))).toBe(false);
    expect(hasStalledCondition(scanning({ status: "failed" }))).toBe(false);
  });
});
