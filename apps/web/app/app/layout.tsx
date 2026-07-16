import { AppShell } from "@/components/app-shell";
import { getActiveProjectId } from "@/lib/active-project";
import { requireUser } from "@/lib/auth";
import { getProjects } from "@/lib/nope-data";

export default async function DashboardLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const [user, projects] = await Promise.all([requireUser(), getProjects()]);
  const activeProjectId = await getActiveProjectId(projects);
  return <AppShell userEmail={user.email} projects={projects} activeProjectId={activeProjectId}>{children}</AppShell>;
}
