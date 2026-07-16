"use client";

import { useRef, useState, useCallback, useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import type { Scan } from "@/lib/types";

const FALLOFF_CURVES = {
  linear: (p: number) => p,
  smooth: (p: number) => p * p * (3 - 2 * p),
  sharp: (p: number) => p * p * p,
};

const routeItems = [
  { href: "/app/projects/local", label: "Overview" },
  { href: "/app/projects/local/findings", label: "Findings" },
  { href: "/app/projects/local/attack-map", label: "Attack Map" },
  { href: "/app/projects/local/coverage", label: "Coverage" },
  { href: "/app/projects/local/scans", label: "Scans" },
  { href: "/app/projects/local/assets", label: "Assets" },
  { href: "/app/projects/local/reports", label: "Reports" },
  { href: "/app/projects/local/settings", label: "Settings" },
];

type BitsSidebarProps = {
  items: string[];
  accentColor?: string;
  textColor?: string;
  markerColor?: string;
  showIndex?: boolean;
  showMarker?: boolean;
  proximityRadius?: number;
  maxShift?: number;
  falloff?: keyof typeof FALLOFF_CURVES;
  markerLength?: number;
  markerGap?: number;
  tickScale?: number;
  scaleTick?: boolean;
  itemGap?: number;
  fontSize?: number;
  smoothing?: number;
  defaultActive?: number | null;
  onItemClick?: (index: number, label: string) => void;
  className?: string;
};

function BitsLineSidebar({
  items,
  accentColor = "#f01683",
  textColor = "#c4c4c4",
  markerColor = "#6c6c6c",
  showIndex = true,
  showMarker = true,
  proximityRadius = 100,
  maxShift = 30,
  falloff = "smooth",
  markerLength = 60,
  markerGap = 0,
  tickScale = 0.5,
  scaleTick = true,
  itemGap = 20,
  fontSize = 1.1,
  smoothing = 100,
  defaultActive = null,
  onItemClick,
  className = "",
}: BitsSidebarProps) {
  const listRef = useRef<HTMLUListElement | null>(null);
  const itemRefs = useRef<Array<HTMLLIElement | null>>([]);
  const targetsRef = useRef<number[]>([]);
  const currentRef = useRef<number[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastRef = useRef(0);
  const activeRef = useRef(defaultActive);
  const smoothingRef = useRef(smoothing);
  const [activeIndex, setActiveIndex] = useState(defaultActive);

  activeRef.current = activeIndex;
  smoothingRef.current = smoothing;

  const runFrame = useCallback((now: number) => {
    const dt = Math.min((now - lastRef.current) / 1000, 0.05);
    lastRef.current = now;
    const tau = Math.max(smoothingRef.current, 1) / 1000;
    const k = 1 - Math.exp(-dt / tau);

    let moving = false;
    const elements = itemRefs.current;
    for (let i = 0; i < elements.length; i += 1) {
      const el = elements[i];
      if (!el) continue;
      const target = Math.max(targetsRef.current[i] || 0, activeRef.current === i ? 1 : 0);
      const cur = currentRef.current[i] || 0;
      const next = cur + (target - cur) * k;
      const settled = Math.abs(target - next) < 0.0015;
      const value = settled ? target : next;
      currentRef.current[i] = value;
      el.style.setProperty("--effect", value.toFixed(4));
      if (!settled) moving = true;
    }

    rafRef.current = moving ? requestAnimationFrame(runFrame) : null;
  }, []);

  const startLoop = useCallback(() => {
    if (rafRef.current != null) return;
    lastRef.current = performance.now();
    rafRef.current = requestAnimationFrame(runFrame);
  }, [runFrame]);

  const handlePointerMove = useCallback(
    (event: React.PointerEvent<HTMLUListElement>) => {
      const list = listRef.current;
      if (!list) return;
      const rect = list.getBoundingClientRect();
      const pointerY = event.clientY - rect.top;
      const ease = FALLOFF_CURVES[falloff] ?? FALLOFF_CURVES.linear;
      const elements = itemRefs.current;
      for (let i = 0; i < elements.length; i += 1) {
        const el = elements[i];
        if (!el) continue;
        const center = el.offsetTop + el.offsetHeight / 2;
        const distance = Math.abs(pointerY - center);
        targetsRef.current[i] = ease(Math.max(0, 1 - distance / proximityRadius));
      }
      startLoop();
    },
    [falloff, proximityRadius, startLoop],
  );

  const handlePointerLeave = useCallback(() => {
    targetsRef.current = targetsRef.current.map(() => 0);
    startLoop();
  }, [startLoop]);

  const handleClick = useCallback(
    (index: number, label: string) => {
      setActiveIndex(index);
      onItemClick?.(index, label);
    },
    [onItemClick],
  );

  useEffect(() => {
    setActiveIndex(defaultActive);
  }, [defaultActive]);

  useEffect(() => {
    startLoop();
  }, [activeIndex, startLoop]);

  useEffect(
    () => () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    },
    [],
  );

  return (
    <nav
      className={`line-sidebar${showMarker ? " line-sidebar--markers" : ""}${scaleTick ? " line-sidebar--scale-tick" : ""}${className ? ` ${className}` : ""}`}
      style={
        {
          "--accent-color": accentColor,
          "--text-color": textColor,
          "--marker-color": markerColor,
          "--marker-length": `${markerLength}px`,
          "--marker-gap": `${markerGap}px`,
          "--tick-scale": tickScale,
          "--max-shift": `${maxShift}px`,
          "--item-gap": `${itemGap}px`,
          "--font-size": `${fontSize}rem`,
          "--smoothing": `${smoothing}ms`,
        } as React.CSSProperties
      }
    >
      <ul ref={listRef} className="line-sidebar__list" onPointerMove={handlePointerMove} onPointerLeave={handlePointerLeave}>
        {items.map((label, index) => (
          <li
            key={`${label}-${index}`}
            ref={(el) => {
              itemRefs.current[index] = el;
            }}
            className="line-sidebar__item"
            aria-current={activeIndex === index ? "true" : undefined}
            onClick={() => handleClick(index, label)}
          >
            {showMarker ? <span className="line-sidebar__marker" aria-hidden="true" /> : null}
            <span className="line-sidebar__label">
              {showIndex ? <span className="line-sidebar__index">{String(index + 1).padStart(2, "0")}</span> : null}
              <span className="line-sidebar__text">{label}</span>
            </span>
          </li>
        ))}
      </ul>
    </nav>
  );
}

export function LineSidebar({ scans }: Readonly<{ scans: Scan[] }>) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const activeIndex = Math.max(
    0,
    routeItems.findIndex((item) => pathname === item.href || (item.href !== "/app/projects/local" && pathname.startsWith(item.href))),
  );
  const selectedScan = searchParams.get("scan") ?? scans[0]?.id ?? "";
  const selectedScanRecord = scans.find((scan) => scan.id === selectedScan) ?? scans[0] ?? null;
  const labelFor = (scan: Scan, index: number) => {
    if (scan.repository_name && scan.repository_name !== "Uploaded ZIP") return scan.repository_name;
    return scan.id || `Upload ${index + 1}`;
  };

  const hrefFor = (href: string, scanId = selectedScan) => {
    const params = new URLSearchParams();
    if (scanId) params.set("scan", scanId);
    return `${href}${params.toString() ? `?${params.toString()}` : ""}`;
  };

  return (
    <aside className="sidebar-frame" aria-label="Project navigation">
      <Link className="sidebar-wordmark" href="/">
        NOPE<span className="wordmark-dot">.</span>
      </Link>
      <BitsLineSidebar
        items={routeItems.map((item) => item.label)}
        accentColor="#f02a56"
        textColor="#a9b0ab"
        markerColor="rgba(255, 255, 255, 0.28)"
        defaultActive={activeIndex}
        proximityRadius={100}
        maxShift={30}
        markerLength={60}
        itemGap={20}
        fontSize={1.05}
        onItemClick={(index) => router.push(hrefFor(routeItems[index]?.href ?? "/app/projects/local"))}
      />
      <div className="sidebar-scan-switcher">
        <label htmlFor="active-scan">Active scan</label>
        <div className="sidebar-select-shell">
          <select
            id="active-scan"
            value={selectedScan}
            onChange={(event) => router.push(hrefFor(pathname, event.target.value))}
            disabled={scans.length === 0}
          >
            {scans.length === 0 ? <option value="">No scans yet</option> : null}
            {scans.map((scan, index) => (
              <option key={scan.id} value={scan.id}>
                {labelFor(scan, index)} - {scan.status}
              </option>
            ))}
          </select>
        </div>
        {selectedScanRecord ? (
          <form action="/api/delete-scan" method="post">
            <input name="scanId" type="hidden" value={selectedScanRecord.id} />
            <button className="sidebar-delete" type="submit">
              Delete selected scan
            </button>
          </form>
        ) : null}
        {selectedScan ? <span className="mono">{selectedScan}</span> : <span className="muted">Run a scan to pin a file.</span>}
      </div>
    </aside>
  );
}
