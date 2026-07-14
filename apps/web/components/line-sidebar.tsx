"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useRouter } from "next/navigation";

const FALLOFF_CURVES = {
  linear: (p: number) => p,
  smooth: (p: number) => p * p * (3 - 2 * p),
  sharp: (p: number) => p * p * p,
};

const links = [
  { href: "/app/projects/local", label: "Overview" },
  { href: "/app/projects/local/findings", label: "Findings" },
  { href: "/app/projects/local/attack-map", label: "Attack Map" },
  { href: "/app/projects/local/coverage", label: "Coverage" },
  { href: "/app/projects/local/scans", label: "Scans" },
  { href: "/app/projects/local/assets", label: "Assets" },
  { href: "/app/projects/local/reports", label: "Reports" },
  { href: "/app/projects/local/settings", label: "Settings" },
];

export function LineSidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const listRef = useRef<HTMLUListElement | null>(null);
  const itemRefs = useRef<Array<HTMLLIElement | null>>([]);
  const targetsRef = useRef<number[]>([]);
  const currentRef = useRef<number[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastRef = useRef(0);
  const defaultActive = Math.max(
    0,
    links.findIndex((link) => pathname === link.href || (link.href !== "/app/projects/local" && pathname.startsWith(link.href))),
  );
  const [activeIndex, setActiveIndex] = useState(defaultActive);

  useEffect(() => {
    setActiveIndex(defaultActive);
  }, [defaultActive]);

  const runFrame = useCallback((now: number) => {
    const dt = Math.min((now - lastRef.current) / 1000, 0.05);
    lastRef.current = now;
    const k = 1 - Math.exp(-dt / 0.1);
    let moving = false;
    for (let i = 0; i < itemRefs.current.length; i += 1) {
      const el = itemRefs.current[i];
      if (!el) continue;
      const target = Math.max(targetsRef.current[i] || 0, activeIndex === i ? 1 : 0);
      const cur = currentRef.current[i] || 0;
      const next = cur + (target - cur) * k;
      const settled = Math.abs(target - next) < 0.0015;
      const value = settled ? target : next;
      currentRef.current[i] = value;
      el.style.setProperty("--effect", value.toFixed(4));
      if (!settled) moving = true;
    }
    rafRef.current = moving ? requestAnimationFrame(runFrame) : null;
  }, [activeIndex]);

  const startLoop = useCallback(() => {
    if (rafRef.current != null) return;
    lastRef.current = performance.now();
    rafRef.current = requestAnimationFrame(runFrame);
  }, [runFrame]);

  const handlePointerMove = useCallback((event: React.PointerEvent<HTMLUListElement>) => {
    const list = listRef.current;
    if (!list) return;
    const rect = list.getBoundingClientRect();
    const pointerY = event.clientY - rect.top;
    const ease = FALLOFF_CURVES.smooth;
    for (let i = 0; i < itemRefs.current.length; i += 1) {
      const el = itemRefs.current[i];
      if (!el) continue;
      const center = el.offsetTop + el.offsetHeight / 2;
      const distance = Math.abs(pointerY - center);
      targetsRef.current[i] = ease(Math.max(0, 1 - distance / 110));
    }
    startLoop();
  }, [startLoop]);

  const handlePointerLeave = useCallback(() => {
    targetsRef.current = targetsRef.current.map(() => 0);
    startLoop();
  }, [startLoop]);

  useEffect(() => {
    startLoop();
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, [startLoop]);

  return (
    <aside className="sidebar-frame" aria-label="Project navigation">
      <Link className="sidebar-wordmark" href="/">
        NOPE.
      </Link>
      <nav className="line-sidebar line-sidebar--markers line-sidebar--scale-tick">
        <ul ref={listRef} className="line-sidebar__list" onPointerMove={handlePointerMove} onPointerLeave={handlePointerLeave}>
          {links.map((link, index) => (
            <li
              key={link.href}
              ref={(el) => {
                itemRefs.current[index] = el;
              }}
              className="line-sidebar__item"
              aria-current={activeIndex === index ? "true" : undefined}
              onClick={() => {
                setActiveIndex(index);
                router.push(link.href);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  setActiveIndex(index);
                  router.push(link.href);
                }
              }}
              tabIndex={0}
            >
              <span className="line-sidebar__marker" aria-hidden="true" />
              <span className="line-sidebar__label">
                <span className="line-sidebar__index">{String(index + 1).padStart(2, "0")}</span>
                <span className="line-sidebar__text">{link.label}</span>
              </span>
            </li>
          ))}
        </ul>
      </nav>
    </aside>
  );
}
