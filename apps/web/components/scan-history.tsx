"use client";

import type { CSSProperties } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { Scan } from "@/lib/types";

type ScanEventState = {
  status: string;
  progress: number;
  stages?: Array<{ status?: string }>;
};

const ACTIVE_STATUSES = new Set(["preparing", "queued", "running"]);
const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled", "partial"]);
type ScanWithStages = Scan & { stages?: Array<{ status?: string }> };
const DONE_STAGE_STATUSES = new Set(["completed", "partial", "failed", "skipped", "cancelled", "timed out"]);

function labelFor(scan: Scan, index: number) {
  if (scan.repository_name && scan.repository_name !== "Uploaded ZIP") return scan.repository_name;
  return scan.id || `Upload ${index + 1}`;
}

function initialProgress(scan: Scan) {
  if (TERMINAL_STATUSES.has(scan.status)) return 100;
  const stages = (scan as ScanWithStages).stages ?? [];
  if (scan.status === "running" && stages.length) {
    return progressFromStages(scan.status, stages);
  }
  if (scan.status === "running") return 15;
  if (scan.status === "queued") return 0;
  if (scan.status === "preparing") return 3;
  return 0;
}

function progressFromStages(status: string, stages: Array<{ status?: string }> = []) {
  if (TERMINAL_STATUSES.has(status)) return 100;
  if (status === "queued") return 0;
  if (status === "preparing") return 3;
  if (!stages.length) return status === "running" ? 15 : 0;
  const done = stages.filter((stage) => DONE_STAGE_STATUSES.has(String(stage.status ?? ""))).length;
  const expected = stages.length > 1 ? stages.length : 8;
  return Math.max(status === "running" ? 15 : 0, Math.min(99, Math.round((done / expected) * 100)));
}

function normalizeEvent(event: ScanEventState) {
  const eventProgress = Number.isFinite(Number(event.progress)) ? Number(event.progress) : 0;
  const stageProgress = progressFromStages(event.status, event.stages);
  return {
    status: event.status,
    progress: Math.max(0, Math.min(100, Math.max(eventProgress, stageProgress))),
    stages: event.stages,
  };
}

export function ScanHistory({ scans, selectedId, projectId }: { scans: Scan[]; selectedId?: string | null; projectId?: string | null }) {
  const router = useRouter();
  const [live, setLive] = useState<Record<string, ScanEventState>>(() =>
    Object.fromEntries(scans.map((scan) => [scan.id, { status: scan.status, progress: initialProgress(scan) }])),
  );
  const refreshedTerminalsRef = useRef(new Set<string>());

  const activeIds = useMemo(
    () => scans.filter((scan) => ACTIVE_STATUSES.has(live[scan.id]?.status ?? scan.status)).map((scan) => scan.id),
    [live, scans],
  );
  const activeKey = activeIds.join("|");

  useEffect(() => {
    setLive((current) => {
      const next = { ...current };
      for (const scan of scans) {
        next[scan.id] ??= { status: scan.status, progress: initialProgress(scan) };
      }
      return next;
    });
  }, [scans]);

  useEffect(() => {
    const ids = activeKey ? activeKey.split("|") : [];
    if (!ids.length) return;
    let cancelled = false;

    async function poll() {
      const updates = await Promise.all(
        ids.map(async (scanId) => {
          try {
            const response = await fetch(`/api/scan-events/${encodeURIComponent(scanId)}?t=${Date.now()}`, {
              cache: "no-store",
              credentials: "same-origin",
              headers: { "cache-control": "no-cache" },
            });
            if (!response.ok) return null;
            const event = (await response.json()) as ScanEventState;
            return [scanId, normalizeEvent(event)] as const;
          } catch {
            return null;
          }
        }),
      );
      if (cancelled) return;
      setLive((current) => {
        const next = { ...current };
        let changed = false;
        for (const update of updates) {
          if (!update) continue;
          const previous = current[update[0]];
          if (!previous || previous.status !== update[1].status || previous.progress !== update[1].progress) {
            next[update[0]] = update[1];
            changed = true;
          }
        }
        return changed ? next : current;
      });
      const terminalIds = updates
        .filter((update): update is NonNullable<typeof update> => Boolean(update))
        .filter(([, event]) => !ACTIVE_STATUSES.has(event.status))
        .map(([scanId]) => scanId);
      if (terminalIds.length) {
        const pending = terminalIds.filter((scanId) => !refreshedTerminalsRef.current.has(scanId));
        if (pending.length) {
          pending.forEach((scanId) => refreshedTerminalsRef.current.add(scanId));
          window.setTimeout(() => router.refresh(), 0);
        }
      }
    }

    poll();
    const timer = window.setInterval(poll, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeKey, router]);

  return (
    <div className="scan-history-list">
      {scans.map((scan, index) => {
        const state = live[scan.id] ?? { status: scan.status, progress: initialProgress(scan) };
        const progressStyle = { "--scan-progress": `${state.progress}%` } as CSSProperties;
        return (
          <article className={`scan-history-row${scan.id === selectedId ? " selected-row" : ""}`} key={scan.id} style={progressStyle}>
            <a
              className="scan-history-main"
              href={`${projectId ? `/app/projects/local/scans/${encodeURIComponent(projectId)}` : "/app/projects/local/scans"}?scan=${encodeURIComponent(scan.id)}`}
            >
              <span className="scan-history-title mono">{labelFor(scan, index)}</span>
              <span className={`scan-status scan-status-${state.status}`}>{state.status}</span>
              <span className="scan-history-verdict">{scan.verdict}</span>
              <span className="scan-progress-orb" aria-label={`${state.progress}% complete`}>
                {state.progress}<small>%</small>
              </span>
            </a>
            <form action="/api/delete-scan" method="post">
              <input name="scanId" type="hidden" value={scan.id} />
              {projectId ? <input name="projectId" type="hidden" value={projectId} /> : null}
              <button className="button ghost danger-button" type="submit">Delete</button>
            </form>
          </article>
        );
      })}
      {scans.length === 0 ? <p className="muted scan-history-empty">No scans yet.</p> : null}
    </div>
  );
}
