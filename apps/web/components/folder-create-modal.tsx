"use client";

import { useState } from "react";
import { Plus, X } from "lucide-react";

export function FolderCreateModal({ error }: { error?: string }) {
  const [open, setOpen] = useState(Boolean(error));

  return (
    <>
      <button className="folder-create-card" type="button" onClick={() => setOpen(true)}>
        <span className="folder-create-icon"><Plus size={24} /></span>
        <span>
          <strong>New folder</strong>
          <small>Create a project workspace</small>
        </span>
      </button>
      <div className={`folder-modal${open ? " folder-modal-open" : ""}`} aria-hidden={!open}>
        <button className="folder-modal-backdrop" type="button" onClick={() => setOpen(false)} aria-label="Close folder modal" />
        <section className="folder-modal-panel" aria-label="Create folder">
          <div className="panel-title">
            <div>
              <p className="section-kicker">Folder</p>
              <h2>Create project folder</h2>
            </div>
            <button className="icon-button" type="button" onClick={() => setOpen(false)} aria-label="Close">
              <X size={18} />
            </button>
          </div>
          {error ? <p className="login-error">{error}</p> : null}
          <form className="compact-form" action="/api/projects" method="post">
            <input className="input-shell" name="name" placeholder="Folder name" required />
            <input className="input-shell" name="repository" placeholder="Repo label" />
            <input className="input-shell" name="targetUrl" type="url" placeholder="URL" />
            <button className="button primary" type="submit">Create folder</button>
          </form>
        </section>
      </div>
    </>
  );
}
