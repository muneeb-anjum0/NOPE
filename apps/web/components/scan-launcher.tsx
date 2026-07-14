import { Upload } from "lucide-react";

export function ScanLauncher() {
  return (
    <form className="app-grid" action="/api/start-scan" method="post" encType="multipart/form-data">
      <label className="dropzone" htmlFor="repository">
        <span>
          <Upload size={22} />
          <br />
          Drop a repository ZIP or choose a file
          <br />
          <span className="mono muted">Zip Slip checks, file limits, cleanup</span>
        </span>
        <input id="repository" name="repository" type="file" accept=".zip" style={{ display: "none" }} />
      </label>
      <input className="input-shell" name="targetUrl" type="url" placeholder="https://your-authorized-app.example" />
      <select className="select-shell" name="depth" defaultValue="full" aria-label="Scan depth">
        <option value="quick">Quick: secrets, dependencies, headers</option>
        <option value="full">Full: repository, code graph, custom rules, AI review</option>
        <option value="deep">Deep: sandbox and dynamic testing when configured</option>
      </select>
      <label className="checkbox-line">
        <input name="confirmed" type="checkbox" />
        <span>I own this target or have explicit permission to test it.</span>
      </label>
      <button className="button primary" type="submit">
        Start evidence scan
      </button>
    </form>
  );
}
