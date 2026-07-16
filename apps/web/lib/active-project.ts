import { cookies } from "next/headers";
import type { Project, Scan } from "@/lib/types";

export const ACTIVE_PROJECT_COOKIE = "nope_active_project";

export async function getActiveProjectId(projects: Project[], explicitProjectId?: string | null) {
  if (explicitProjectId && projects.some((project) => project.id === explicitProjectId)) {
    return explicitProjectId;
  }
  const cookieProjectId = (await cookies()).get(ACTIVE_PROJECT_COOKIE)?.value ?? null;
  if (cookieProjectId && projects.some((project) => project.id === cookieProjectId)) {
    return cookieProjectId;
  }
  return projects[0]?.id ?? null;
}

export function scansForProject(scans: Scan[], projectId?: string | null) {
  return projectId ? scans.filter((scan) => scan.project_id === projectId) : [];
}
