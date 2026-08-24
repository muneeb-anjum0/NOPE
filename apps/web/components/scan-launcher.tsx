"use client";

import { useEffect, useRef, useState } from "react";
import { Upload } from "lucide-react";

const MAX_ZIP_BYTES = 512 * 1024 * 1024;
type UploadState = "idle" | "uploading" | "uploaded";

export function ScanLauncher({ projectId, scaffoldWarning }: { projectId?: string; scaffoldWarning?: string }) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [fileName, setFileName] = useState("");
  const [uploadError, setUploadError] = useState("");
  const [uploadState, setUploadState] = useState<UploadState>("idle");
  const [uploadProgress, setUploadProgress] = useState(0);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setHydrated(true);
  }, []);

  const setFiles = (files: FileList | null) => {
    const file = files?.[0];
    if (!file) return;
    if (file.size > MAX_ZIP_BYTES) {
      if (inputRef.current) inputRef.current.value = "";
      setFileName("");
      setUploadError(`ZIP files must be 512 MiB or smaller. “${file.name}” is ${(file.size / (1024 * 1024)).toFixed(1)} MiB.`);
      setUploadState("idle");
      setUploadProgress(0);
      return;
    }
    if (inputRef.current) {
      const transfer = new DataTransfer();
      transfer.items.add(file);
      inputRef.current.files = transfer.files;
    }
    setFileName(file.name);
    setUploadError("");
    setUploadState("idle");
    setUploadProgress(0);
  };

  const submitScan = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const file = inputRef.current?.files?.[0];
    if (file && file.size > MAX_ZIP_BYTES) {
      setUploadError(`ZIP files must be 512 MiB or smaller. “${file.name}” is ${(file.size / (1024 * 1024)).toFixed(1)} MiB.`);
      return;
    }

    setUploadError("");
    setUploadState("uploading");
    setUploadProgress(0);
    const request = new XMLHttpRequest();
    request.open("POST", form.action);
    request.upload.addEventListener("progress", (progressEvent) => {
      if (!progressEvent.lengthComputable) return;
      const percent = Math.min(100, Math.round((progressEvent.loaded / progressEvent.total) * 100));
      setUploadProgress(percent);
      if (percent === 100) setUploadState("uploaded");
    });
    request.upload.addEventListener("load", () => {
      setUploadProgress(100);
      setUploadState("uploaded");
    });
    request.addEventListener("load", () => {
      if (request.status >= 200 && request.status < 400) {
        window.location.assign(request.responseURL || form.action);
        return;
      }
      setUploadState("idle");
      setUploadError(`The scan request failed with status ${request.status}. Please try again.`);
    });
    request.addEventListener("error", () => {
      setUploadState("idle");
      setUploadError("The upload was interrupted. Check the connection and try again.");
    });
    request.addEventListener("abort", () => {
      setUploadState("idle");
      setUploadError("The upload was cancelled before it completed.");
    });
    request.send(new FormData(form));
  };

  return (
    <form
      className="app-grid"
      action={projectId ? `/api/start-scan?projectId=${encodeURIComponent(projectId)}` : "/api/start-scan"}
      method="post"
      encType="multipart/form-data"
      data-scan-launcher-ready={hydrated ? "true" : "false"}
      onSubmit={submitScan}
    >
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
      {uploadError ? <p className="login-error" role="alert">{uploadError}</p> : null}
      {uploadState !== "idle" ? (
        <div className={`upload-progress-card${uploadState === "uploaded" ? " is-complete" : ""}`} aria-live="polite">
          <div className="upload-progress-copy">
            <strong>{uploadState === "uploaded" ? "Upload complete" : `Uploading ${fileName || "repository"}`}</strong>
            <span className="mono">{uploadProgress}%</span>
          </div>
          <div
            aria-label="Repository upload progress"
            aria-valuemax={100}
            aria-valuemin={0}
            aria-valuenow={uploadProgress}
            className="upload-progress-track"
            role="progressbar"
          >
            <span style={{ width: `${uploadProgress}%` }} />
          </div>
          <p>{uploadState === "uploaded" ? "Repository received. NOPE is creating the scan…" : "Keep this page open while the ZIP is transferred."}</p>
        </div>
      ) : null}
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
      <button className="button primary" disabled={uploadState !== "idle"} type="submit">
        {uploadState === "idle" ? "Start evidence scan" : uploadState === "uploaded" ? "Creating scan…" : `Uploading… ${uploadProgress}%`}
      </button>
    </form>
  );
}
