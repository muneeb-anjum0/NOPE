"use client";

import { useEffect, useRef, useState } from "react";
import { Upload } from "lucide-react";

export function ScanLauncher({ projectId, scaffoldWarning }: { projectId?: string; scaffoldWarning?: string }) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [fileName, setFileName] = useState("");
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setHydrated(true);
  }, []);

  const setFiles = (files: FileList | null) => {
    const file = files?.[0];
    if (!file) return;
    if (inputRef.current) {
      const transfer = new DataTransfer();
      transfer.items.add(file);
      inputRef.current.files = transfer.files;
    }
    setFileName(file.name);
  };

  return (
    <form className="app-grid" action="/api/start-scan" method="post" encType="multipart/form-data" data-scan-launcher-ready={hydrated ? "true" : "false"}>
      {projectId ? <input name="projectId" type="hidden" value={projectId} /> : null}
      <label
        className={`dropzone${fileName ? " dropzone-selected" : ""}`}
        htmlFor="repository"
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault();
          setFiles(event.dataTransfer.files);
        }}
      >
        <span>
          <Upload className="dropzone-icon" size={22} />
          <br />
          <span className={fileName ? "dropzone-file-name" : undefined}>{fileName || "Drop a repository ZIP or choose a file"}</span>
          <br />
          <span className="mono muted">Zip Slip checks, file limits, cleanup</span>
        </span>
        <input
          ref={inputRef}
          id="repository"
          name="repository"
          type="file"
          accept=".zip"
          style={{ display: "none" }}
          onChange={(event) => setFiles(event.currentTarget.files)}
        />
      </label>
      <input className="input-shell" name="targetUrl" type="url" placeholder="https://your-authorized-app.example" />
      <input name="repositoryName" type="hidden" value={fileName} />
      <select className="select-shell" name="depth" defaultValue="full" aria-label="Scan depth">
        <option value="quick">Quick: secrets, dependencies, headers</option>
        <option value="full">Full: repository, code graph, custom rules, AI review</option>
        <option value="deep">Deep: sandbox and dynamic testing when configured</option>
      </select>
      <label className="checkbox-line">
        <input name="confirmed" type="checkbox" />
        <span>I own this target or have explicit permission to test it.</span>
      </label>
      {scaffoldWarning ? <p className="login-error">{scaffoldWarning}</p> : null}
      <label className="checkbox-line compact-checkbox">
        <input name="forceScaffold" type="checkbox" />
        <span>Upload anyway if this ZIP looks like a different project.</span>
      </label>
      <button className="button primary" type="submit">
        Start evidence scan
      </button>
    </form>
  );
}
