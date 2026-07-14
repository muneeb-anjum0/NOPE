"use client";

import { Activity, Boxes, FileText, Gauge, Map, Radar, Search, Settings, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/app/projects/local", label: "Overview", icon: Gauge },
  { href: "/app/projects/local/findings", label: "Findings", icon: ShieldAlert },
  { href: "/app/projects/local/attack-map", label: "Attack Map", icon: Map },
  { href: "/app/projects/local/coverage", label: "Coverage", icon: Radar },
  { href: "/app/projects/local/scans", label: "Scans", icon: Activity },
  { href: "/app/projects/local/assets", label: "Assets", icon: Boxes },
  { href: "/app/projects/local/reports", label: "Reports", icon: FileText },
  { href: "/app/projects/local/settings", label: "Settings", icon: Settings },
];

export function LineSidebar() {
  const pathname = usePathname();
  return (
    <aside className="line-sidebar" aria-label="Project navigation">
      <Link className="side-logo" href="/" aria-label="NOPE landing">
        N
      </Link>
      <nav className="side-nav">
        {links.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== "/app/projects/local" && pathname.startsWith(href));
          return (
            <Link className={`side-link ${active ? "active" : ""}`} href={href} data-label={label} key={href}>
              <Icon size={20} aria-hidden />
              <span className="sr-only">{label}</span>
            </Link>
          );
        })}
      </nav>
      <Link className="side-link" href="/app/projects/local/findings" data-label="Search findings">
        <Search size={20} aria-hidden />
        <span className="sr-only">Search findings</span>
      </Link>
    </aside>
  );
}
