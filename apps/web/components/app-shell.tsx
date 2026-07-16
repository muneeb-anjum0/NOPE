import { LineSidebar } from "@/components/line-sidebar";
import type { Scan } from "@/lib/types";

export function AppShell({ children, userEmail, scans }: Readonly<{ children: React.ReactNode; userEmail: string; scans: Scan[] }>) {
  return (
    <div className="app-layout">
      <LineSidebar scans={scans} />
      <main className="app-main">
        <div className="sr-only">Signed in as {userEmail}</div>
        <div className="app-content">{children}</div>
      </main>
    </div>
  );
}
