"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import type { Project } from "@/lib/types";

const primaryItems = [
  { href: "/app/projects/local", label: "Overview", note: "What needs attention" },
  { href: "/app/projects/local/scans", label: "Scans", note: "Upload and track" },
  { href: "/app/projects/local/findings", label: "Findings", note: "Review real signals" },
  { href: "/app/projects/local/investigations", label: "Investigate", note: "Prove and remediate" },
  { href: "/app/projects/local/settings", label: "Settings", note: "Configure NOPE" },
];

const analysisItems = [
  { href: "/app/projects/local/coverage", label: "Coverage" },
  { href: "/app/projects/local/attack-map", label: "Attack map" },
  { href: "/app/projects/local/assets", label: "Assets" },
  { href: "/app/projects/local/search", label: "Repository search" },
];

function matches(pathname: string, href: string) {
  return pathname === href || (href !== "/app/projects/local" && pathname.startsWith(`${href}/`));
}

export function LineSidebar({ projects, activeProjectId }: Readonly<{ projects: Project[]; activeProjectId?: string | null }>) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [collapsed, setCollapsed] = useState(false);
  const analysisActive = analysisItems.some((item) => matches(pathname, item.href));
  const [analysisOpen, setAnalysisOpen] = useState(analysisActive);
  const selectedScan = searchParams.get("scan") ?? "";
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null;
  const currentPath = `${pathname}${searchParams.toString() ? `?${searchParams.toString()}` : ""}`;

  useEffect(() => {
    if (analysisActive) setAnalysisOpen(true);
  }, [analysisActive]);

  const hrefFor = (href: string) => {
    if (!selectedScan || href.endsWith("/scans") || href.endsWith("/settings")) return href;
    return `${href}?scan=${encodeURIComponent(selectedScan)}`;
  };

  return (
    <aside className={`sidebar-frame product-sidebar${collapsed ? " is-collapsed" : ""}`} aria-label="Project navigation">
      <div className="sidebar-header">
        <Link className="sidebar-wordmark" href="/app/projects/local" aria-label="NOPE home">
          <span className="sidebar-wordmark-text">NOPE<span className="wordmark-dot">.</span></span>
        </Link>
        <button aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} className="sidebar-collapse-button" type="button" onClick={() => setCollapsed((value) => !value)}>
          <span aria-hidden="true">{collapsed ? "›" : "‹"}</span>
        </button>
      </div>

      <div className="sidebar-project-label">
        <span className="project-pulse" aria-hidden="true" />
        <span><small>Active project</small><strong>{activeProject?.name ?? "Choose a project"}</strong></span>
      </div>

      <nav className="product-navigation" aria-label="Main workflow">
        <span className="sidebar-section-label">Workflow</span>
        <ol className="primary-nav-list">
          {primaryItems.map((item, index) => {
            const active = matches(pathname, item.href);
            return (
              <li key={item.href}>
                <Link className={`product-nav-link${active ? " is-active" : ""}`} href={hrefFor(item.href)} aria-current={active ? "page" : undefined}>
                  <span className="product-nav-number">{String(index + 1).padStart(2, "0")}</span>
                  <span className="product-nav-copy"><strong>{item.label}</strong><small>{item.note}</small></span>
                </Link>
              </li>
            );
          })}
        </ol>

        <div className={`analysis-nav${analysisOpen ? " is-open" : ""}${analysisActive ? " is-active" : ""}`}>
          <button type="button" onClick={() => setAnalysisOpen((value) => !value)} aria-expanded={analysisOpen}>
            <span>Analyze scan</span><span aria-hidden="true">{analysisOpen ? "−" : "+"}</span>
          </button>
          {analysisOpen ? (
            <div className="analysis-nav-links">
              {analysisItems.map((item) => {
                const active = matches(pathname, item.href);
                return <Link key={item.href} className={active ? "is-active" : ""} href={hrefFor(item.href)}><span>{item.label}</span></Link>;
              })}
            </div>
          ) : null}
        </div>
      </nav>

      <form className="sidebar-folder-context" action="/api/active-project" method="post">
        <label>Switch project</label>
        <input name="returnTo" type="hidden" value={currentPath} />
        <details className="sidebar-folder-picker">
          <summary><span><strong>{activeProject?.name ?? "No project"}</strong><small>{activeProject?.repository || activeProject?.target_url || "Local workspace"}</small></span><span className="sidebar-folder-count mono">{projects.length}</span></summary>
          <div className="sidebar-folder-menu">
            {projects.length === 0 ? <span className="sidebar-folder-empty">Create a project in Scans</span> : null}
            {projects.map((project) => (
              <button className={project.id === activeProjectId ? "is-active" : ""} key={project.id} name="projectId" type="submit" value={project.id}>
                <span><strong>{project.name}</strong><small>{project.repository || project.target_url || "Local workspace"}</small></span>
              </button>
            ))}
          </div>
        </details>
      </form>
    </aside>
  );
}
