import Link from "next/link";
import { MoreHorizontal, Trash2 } from "lucide-react";
import { FolderCreateModal } from "@/components/folder-create-modal";
import { PinkDotText } from "@/components/pink-dot-text";
import { getProjects, getScans } from "@/lib/nope-data";
import type { Project } from "@/lib/types";

export default async function ScansPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const params = await searchParams;
  const [projects, scans] = await Promise.all([getProjects(), getScans()]);

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Scans</p>
          <h1><PinkDotText text="Project folders." /></h1>
          <p>Create a folder for each app you want to track, then scan ZIPs inside that folder only.</p>
        </div>
      </section>

      <section className="folder-shelf">
        <FolderCreateModal error={params.error} />
        {projects.map((project) => (
          <FolderLink
            key={project.id}
            project={project}
            count={scans.filter((scan) => scan.project_id === project.id).length}
          />
        ))}
      </section>

      {projects.length === 0 ? (
        <div className="app-panel empty-folder-panel">
          <p className="muted">No folders yet. Use the plus card to create the first project workspace.</p>
        </div>
      ) : null}
    </>
  );
}

function FolderLink({ project, count }: { project: Project; count: number }) {
  const href = `/api/active-project?projectId=${encodeURIComponent(project.id)}&returnTo=${encodeURIComponent(`/app/projects/local/scans/${project.id}`)}`;
  return (
    <article className="folder-link folder-card">
      <Link className="folder-card-main" href={href}>
        <span>
          <strong>{project.name}</strong>
          <small>{project.repository || project.target_url || "folder workspace"}</small>
        </span>
        <span className="folder-count">{count}</span>
      </Link>
      <details className="folder-card-menu">
        <summary aria-label={`Open ${project.name} folder actions`}>
          <MoreHorizontal size={18} />
        </summary>
        <div className="folder-card-menu-panel">
          <form action="/api/delete-project" method="post">
            <input name="projectId" type="hidden" value={project.id} />
            <button className="folder-delete-action" type="submit">
              <Trash2 size={15} />
              Delete project
            </button>
          </form>
        </div>
      </details>
    </article>
  );
}
