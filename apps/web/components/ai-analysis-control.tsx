"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export function AIAnalysisControl({ scanId, enabled, configured, label }: { scanId: string; enabled: boolean; configured: boolean; label: string }) {
  const router = useRouter(); const [running, setRunning] = useState(false); const [error, setError] = useState(""); const [estimatedBytes, setEstimatedBytes] = useState<number | null>(null);
  useEffect(() => { if (!enabled || !configured) return; void fetch(`/api/scans/${scanId}/ai-context`).then((response) => response.ok ? response.json() : null).then((body: { approximateInputBytes?: number } | null) => setEstimatedBytes(body?.approximateInputBytes ?? null)).catch(() => undefined); }, [configured, enabled, scanId]);
  async function run() { setRunning(true); setError(""); const response = await fetch(`/api/scans/${scanId}/ai-analysis`, { method: "POST" }).catch(() => null); if (!response?.ok) setError(response ? ((await response.json().catch(() => ({}))) as { error?: string }).error ?? "Unable to start AI analysis." : "Unable to start AI analysis."); else { router.refresh(); setTimeout(() => router.refresh(), 1500); } setRunning(false); }
  return <div><button className="button" disabled={running || !enabled || !configured} onClick={() => void run()}>{running ? "STARTING…" : label}</button>{estimatedBytes !== null && <div className="hint" style={{ marginTop: 8 }}>Estimated structured input: ~{Math.ceil(estimatedBytes / 1024)} KiB before tokenization.</div>}{!enabled && <div className="hint" style={{ marginTop: 8 }}>Set AI_ENABLED=true to enable this stage.</div>}{enabled && !configured && <div className="hint" style={{ marginTop: 8 }}>Configure OPENAI_API_KEY on the server.</div>}{error && <div className="error" style={{ marginTop: 8, marginBottom: 0 }}>{error}</div>}</div>;
}
