import type { Scan, SecurityBaseline } from "@/lib/types";

function normalizedSource(value?: string | null) {
  const cleaned = (value ?? "").trim().toLowerCase();
  if (!cleaned || cleaned === "uploaded zip") return null;
  return cleaned;
}

function scanSource(scan: Scan) {
  return normalizedSource(scan.repository_name) ?? normalizedSource(scan.target_url);
}

function baselineSource(baseline: SecurityBaseline) {
  const snapshot = baseline.data?.repository_snapshot;
  const repositoryName = typeof snapshot === "object" && snapshot && "repository_name" in snapshot ? String(snapshot.repository_name ?? "") : "";
  const target = typeof baseline.data?.target === "string" ? baseline.data.target : "";
  return normalizedSource(repositoryName) ?? normalizedSource(target);
}

export function scansAreComparable(current: Scan, reference: Scan) {
  if (current.project_id || reference.project_id) {
    return Boolean(current.project_id && current.project_id === reference.project_id);
  }
  const currentSource = scanSource(current);
  const referenceSource = scanSource(reference);
  return Boolean(currentSource && currentSource === referenceSource);
}

export function baselineIsComparable(scan: Scan, baseline: SecurityBaseline) {
  if (scan.project_id || baseline.project_id) {
    return Boolean(scan.project_id && scan.project_id === baseline.project_id);
  }
  const currentSource = scanSource(scan);
  const referenceSource = baselineSource(baseline);
  return Boolean(currentSource && currentSource === referenceSource);
}
