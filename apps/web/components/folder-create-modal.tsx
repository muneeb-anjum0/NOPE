"use client";

import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { Plus, X } from "lucide-react";

export function FolderCreateModal({ error }: { error?: string }) {
  const [open, setOpen] = useState(Boolean(error));
  const panelRef = useRef<HTMLElement | null>(null);
  const nameRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    nameRef.current?.focus();
    return () => previous?.focus();
  }, [open]);

  function handleDialogKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = Array.from(
      panelRef.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ) ?? [],
    );
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <>
      <button className="folder-create-card" type="button" onClick={() => setOpen(true)}>
        <span className="folder-create-icon"><Plus size={24} /></span>
        <span>
          <strong>New folder</strong>
          <small>Create a project workspace</small>
        </span>
      </button>
      <div className={`folder-modal${open ? " folder-modal-open" : ""}`} aria-hidden={!open} inert={open ? undefined : true}>
        <button className="folder-modal-backdrop" type="button" onClick={() => setOpen(false)} aria-label="Close folder modal" />
        <section
          ref={panelRef}
          className="folder-modal-panel"
          role="dialog"
          aria-modal="true"
          aria-labelledby="folder-modal-title"
          onKeyDown={handleDialogKeyDown}
        >
          <div className="panel-title">
            <div>
              <p className="section-kicker">Folder</p>
              <h2 id="folder-modal-title">Create project folder</h2>
            </div>
            <button className="icon-button" type="button" onClick={() => setOpen(false)} aria-label="Close">
              <X size={18} />
            </button>
          </div>
          {error ? <p className="login-error">{error}</p> : null}
          <form className="compact-form" action="/api/projects" method="post">
            <input ref={nameRef} className="input-shell" name="name" placeholder="Folder name" aria-label="Folder name" required />
            <input className="input-shell" name="repository" placeholder="Repo label" aria-label="Repo label" />
            <input className="input-shell" name="targetUrl" type="url" placeholder="URL" aria-label="Target URL" />
            <button className="button primary" type="submit">Create folder</button>
          </form>
        </section>
      </div>
    </>
  );
}
