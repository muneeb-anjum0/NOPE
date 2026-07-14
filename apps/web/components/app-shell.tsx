import { Brain, Command, Play, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { LineSidebar } from "@/components/line-sidebar";

export function AppShell({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <div className="app-layout">
      <LineSidebar />
      <main className="app-main">
        <header className="app-topbar">
          <div className="project-chip">
            <ShieldCheck size={16} color="var(--passed)" />
            <span>NOPE Local Workspace</span>
            <span className="mono muted">main</span>
          </div>
          <div className="hero-actions" style={{ marginTop: 0 }}>
            <button className="button ghost" type="button" aria-label="Open command palette">
              <Command size={15} /> Command
            </button>
            <Link className="button" href="/app/projects/local/settings">
              <Brain size={15} /> AI status
            </Link>
            <Link className="button primary" href="/app/projects/local/scans">
              <Play size={15} /> Run scan
            </Link>
          </div>
        </header>
        <div className="app-content">{children}</div>
      </main>
    </div>
  );
}
