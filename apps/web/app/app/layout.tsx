import { AppShell } from "@/components/app-shell";
import { requireUser } from "@/lib/auth";
import { getScans } from "@/lib/nope-data";

export default async function DashboardLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const user = await requireUser();
  const scans = await getScans();
  return <AppShell userEmail={user.email} scans={scans}>{children}</AppShell>;
}
