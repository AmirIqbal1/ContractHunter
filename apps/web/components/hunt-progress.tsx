"use client";

import { useEffect, useState } from "react";
import type { AIAnalysisStatus, ReviewStageStatus, ScannerStatus, ScanStatus } from "@contracthunter/core";

const TERMINAL_SCAN_STATUSES: ScanStatus[] = ["completed", "failed"];
const TERMINAL_SCANNER_STATUSES: ScannerStatus[] = ["completed", "failed", "unavailable"];
const AI_WAITING_STATUSES: AIAnalysisStatus[] = ["disabled", "pending"];

export type HuntProgressState = {
  status: ScanStatus;
  aiStatus: AIAnalysisStatus;
  reviewStatus: ReviewStageStatus;
  scannerStatuses: ScannerStatus[];
};

export function elapsedMilliseconds(startedAt: string | null, createdAt: string, completedAt: string | null, now: number): number {
  const start = Date.parse(startedAt ?? createdAt);
  const end = completedAt ? Date.parse(completedAt) : now;
  return Math.max(0, end - start);
}

export function formatElapsed(durationMs: number): string {
  const totalSeconds = Math.floor(durationMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes < 10
    ? `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
    : `${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

export function allScannersTerminal(statuses: ScannerStatus[]): boolean {
  return statuses.length > 0 && statuses.every((status) => TERMINAL_SCANNER_STATUSES.includes(status));
}

export function hasStalledCondition(state: HuntProgressState): boolean {
  return !TERMINAL_SCAN_STATUSES.includes(state.status)
    && allScannersTerminal(state.scannerStatuses)
    && AI_WAITING_STATUSES.includes(state.aiStatus);
}

export function shouldShowStalledWarning(conditionStartedAt: number | null, now: number): boolean {
  return conditionStartedAt !== null && now - conditionStartedAt >= 30_000;
}

export function currentStageLabel(state: HuntProgressState): string {
  if (state.status === "completed") return "Static scan complete";
  if (state.status === "failed") return "Failed";
  if (state.status === "queued") return "Queued";
  if (state.status === "cloning") return "Cloning repository";
  if (state.status === "detecting") return "Detecting project";
  if (state.status === "preparing_dependencies") return "Preparing dependencies";
  if (state.status === "preparing_compiler") return "Preparing compiler";
  if (state.reviewStatus === "pending" || state.reviewStatus === "running") return "Running AI security review";
  if (state.aiStatus === "running") return "Running AI protocol analysis";
  if (allScannersTerminal(state.scannerStatuses) && AI_WAITING_STATUSES.includes(state.aiStatus)) return "Preparing AI analysis";
  return "Running security scanners";
}

function StallWarningTimer() {
  const [secondsObserved, setSecondsObserved] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(() => setSecondsObserved((value) => value + 1), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return secondsObserved >= 30
    ? <div className="stall-warning">Static scanning has finished, but the hunt has not progressed to AI analysis. The scan worker may have been interrupted.</div>
    : null;
}

export function HuntProgress({ state, createdAt, startedAt, completedAt }: {
  state: HuntProgressState;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
}) {
  const active = !TERMINAL_SCAN_STATUSES.includes(state.status);
  const stalledCondition = hasStalledCondition(state);
  const [now, setNow] = useState<number | null>(null);

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);

  const duration = elapsedMilliseconds(startedAt, createdAt, active ? null : completedAt, now ?? Date.parse(startedAt ?? createdAt));

  return <>
    <dl className="progress-details">
      <div className="detail"><dt>Current stage</dt><dd>{currentStageLabel(state)}</dd></div>
      <div className="detail"><dt>Elapsed</dt><dd className="mono">{formatElapsed(duration)}</dd></div>
    </dl>
    {stalledCondition && <StallWarningTimer />}
  </>;
}
