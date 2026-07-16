"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { Scan } from "@/lib/types";

type ScanEventState = {
  status: string;
  progress: number;
};

const ACTIVE_STATUSES = new Set(["preparing", "queued", "running"]);

function labelFor(scan: Scan, index: number) {
  if (scan.repository_name && scan.repository_name !== "Uploaded ZIP") return scan.repository_name;
  return scan.id || `Upload ${index + 1}`;
}

function initialProgress(scan: Scan) {
  if (["completed", "failed", "cancelled", "partial"].includes(scan.status)) return 100;
  if (scan.status === "running") return 35;
  if (scan.status === "queued") return 8;
  if (scan.status === "preparing") return 3;
  return 0;
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
            const response = await fetch(`/api/scan-events/${encodeURIComponent(scanId)}`, { cache: "no-store" });
            if (!response.ok) return null;
            const event = (await response.json()) as ScanEventState;
            return [scanId, { status: event.status, progress: Math.max(0, Math.min(100, event.progress ?? 0)) }] as const;
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
    const timer = window.setInterval(poll, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeKey, router]);

  return (
    <table className="table scan-history-table">
      <tbody>
        {scans.map((scan, index) => {
          const state = live[scan.id] ?? { status: scan.status, progress: initialProgress(scan) };
          return (
            <tr className={scan.id === selectedId ? "selected-row" : ""} key={scan.id}>
              <td>
                <a
                  className="mono"
                  href={`${projectId ? `/app/projects/local/scans/${encodeURIComponent(projectId)}` : "/app/projects/local/scans"}?scan=${encodeURIComponent(scan.id)}`}
                >
                  {labelFor(scan, index)}
                </a>
                <div className="scan-progress-wrap" aria-label={`${state.progress}% complete`}>
                  <div className="scan-progress-bar">
                    <span style={{ width: `${state.progress}%` }} />
                  </div>
                  <span className="scan-progress-percent">{state.progress}%</span>
                </div>
              </td>
              <td><span className={`scan-status scan-status-${state.status}`}>{state.status}</span></td>
              <td>{scan.verdict}</td>
              <td>
                <form action="/api/delete-scan" method="post">
                  <input name="scanId" type="hidden" value={scan.id} />
                  {projectId ? <input name="projectId" type="hidden" value={projectId} /> : null}
                  <button className="button ghost danger-button" type="submit">Delete</button>
                </form>
              </td>
            </tr>
          );
        })}
        {scans.length === 0 ? <tr><td>No scans yet.</td></tr> : null}
      </tbody>
    </table>
  );
}
