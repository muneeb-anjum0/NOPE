import { LineSidebar } from "@/components/line-sidebar";
import { RouteTransition } from "@/components/route-transition";
import type { Project } from "@/lib/types";

export function AppShell({
  children,
  userEmail,
  projects,
  activeProjectId,
}: Readonly<{ children: React.ReactNode; userEmail: string; projects: Project[]; activeProjectId?: string | null }>) {
  return (
    <div className="app-layout" data-brand-skip>
      <LineSidebar projects={projects} activeProjectId={activeProjectId} />
      <main className="app-main">
        <div className="sr-only">Signed in as {userEmail}</div>
        <div className="app-content">
          <RouteTransition>{children}</RouteTransition>
        </div>
      </main>
    </div>
  );
}
