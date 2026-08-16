"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export type ProtocolCostEstimateDTO = { approximateInputBytes: number; estimatedCostDisplay: string };
export function ProtocolCostEstimate({ estimate }: { estimate: ProtocolCostEstimateDTO }) {
  return <div className="hint" style={{ marginTop: 8 }}>Estimated structured input: ~{Math.ceil(estimate.approximateInputBytes / 1024)} KiB. Estimated API cost: ~{estimate.estimatedCostDisplay}. Estimate only — actual cost depends on token usage.</div>;
}

export function AIAnalysisControl({ scanId, enabled, configured, stageRunning, label }: { scanId: string; enabled: boolean; configured: boolean; stageRunning: boolean; label: string }) {
  const router = useRouter(); const [running, setRunning] = useState(false); const [error, setError] = useState(""); const [estimate, setEstimate] = useState<ProtocolCostEstimateDTO | null>(null);
  useEffect(() => { if (!enabled || !configured) return; void fetch(`/api/scans/${scanId}/ai-context`).then((response) => response.ok ? response.json() : null).then(setEstimate).catch(() => undefined); }, [configured, enabled, scanId]);
  async function run() { setRunning(true); setError(""); const response = await fetch(`/api/scans/${scanId}/ai-analysis`, { method: "POST" }).catch(() => null); if (!response?.ok) setError(response ? ((await response.json().catch(() => ({}))) as { error?: string }).error ?? "Unable to start AI analysis." : "Unable to start AI analysis."); else { router.refresh(); setTimeout(() => router.refresh(), 1500); } setRunning(false); }
  return <div><button className="button" disabled={running || stageRunning || !enabled || !configured} onClick={() => void run()}>{running ? "STARTING…" : stageRunning ? "AI ANALYSIS RUNNING…" : label}</button>{estimate && <ProtocolCostEstimate estimate={estimate} />}{!enabled && <div className="hint" style={{ marginTop: 8 }}>Set AI_ENABLED=true to enable this stage.</div>}{enabled && !configured && <div className="hint" style={{ marginTop: 8 }}>Configure OPENAI_API_KEY on the server.</div>}{error && <div className="error" style={{ marginTop: 8, marginBottom: 0 }}>{error}</div>}</div>;
}
