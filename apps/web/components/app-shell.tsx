import { LineSidebar } from "@/components/line-sidebar";

export function AppShell({ children, userEmail }: Readonly<{ children: React.ReactNode; userEmail: string }>) {
  return (
    <div className="app-layout">
      <LineSidebar />
      <main className="app-main">
        <div className="sr-only">Signed in as {userEmail}</div>
        <div className="app-content">{children}</div>
      </main>
    </div>
  );
}
