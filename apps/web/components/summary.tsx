import type { Scan } from "@/lib/types";

export function SeveritySummary({ scan }: { scan: Scan }) {
  const counts = {
    critical: scan.findings.filter((finding) => finding.severity === "critical").length,
    high: scan.findings.filter((finding) => finding.severity === "high").length,
    medium: scan.findings.filter((finding) => finding.severity === "medium").length,
    low: scan.findings.filter((finding) => finding.severity === "low").length,
  };
  return (
    <div className="app-grid cols-4">
      <Metric label="Score" value={String(scan.score)} note={scan.verdict} />
      <Metric label="Coverage" value={`${scan.coverage_percent}%`} note="Not tested is not secure" />
      <Metric label="Critical" value={String(counts.critical)} note="Do not ship unresolved" severity="critical" />
      <Metric label="High" value={String(counts.high)} note={`${counts.medium} medium / ${counts.low} low`} severity="high" />
    </div>
  );
}

export function Metric({ label, value, note, severity }: { label: string; value: string; note: string; severity?: string }) {
  return (
    <div className="app-panel">
      <span className="mono muted">{label}</span>
      <strong className="metric-value" style={severity ? { color: `var(--${severity})` } : undefined}>
        {value}
      </strong>
      <p className="muted">{note}</p>
    </div>
  );
}
