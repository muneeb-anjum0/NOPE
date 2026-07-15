import type { GitHubStatus, Project, ProjectSettings, SystemSettings } from "@/lib/types";

type Props = {
  system: SystemSettings | null;
  project: Project | null;
  projectSettings: ProjectSettings | null;
  github: GitHubStatus | null;
  saveSystem: (formData: FormData) => Promise<void>;
  saveProject: (formData: FormData) => Promise<void>;
  saveGitHub: (formData: FormData) => Promise<void>;
};

export function SettingsForms({ system, project, projectSettings, github, saveSystem, saveProject, saveGitHub }: Props) {
  return (
    <div className="app-grid">
      <form className="stat-panel" action={saveSystem}>
        <h2>System Settings</h2>
        <input className="input-shell" name="qwen_endpoint" defaultValue={system?.qwen_endpoint ?? "http://nope-ai:8080"} />
        <select className="select-shell" name="runtime" defaultValue={system?.runtime ?? "llama.cpp"}>
          <option value="llama.cpp">llama.cpp</option>
          <option value="disabled">Disabled</option>
        </select>
        <div className="app-grid two">
          <input className="input-shell" name="context" type="number" defaultValue={system?.context ?? 4096} min={512} max={32768} />
          <input className="input-shell" name="gpu_layers" type="number" defaultValue={system?.gpu_layers ?? 28} min={0} max={128} />
          <input className="input-shell" name="timeout" type="number" defaultValue={system?.timeout ?? 180} min={5} max={1800} />
          <input className="input-shell" name="output_limit" type="number" defaultValue={system?.output_limit ?? 1024} min={64} max={8192} />
          <input className="input-shell" name="concurrency" type="number" defaultValue={system?.concurrency ?? 1} min={1} max={8} />
          <input className="input-shell" name="scanner_timeout" type="number" defaultValue={system?.scanner_timeout ?? 180} min={5} max={3600} />
        </div>
        <select className="select-shell" name="default_scan_mode" defaultValue={system?.default_scan_mode ?? "full"}>
          <option value="full">Full</option>
          <option value="repository">Repository</option>
          <option value="url">URL</option>
        </select>
        <div className="app-grid two">
          <input className="input-shell" name="retention_days" type="number" defaultValue={system?.retention_days ?? 30} min={1} max={3650} />
          <input className="input-shell" name="artifact_limit_mb" type="number" defaultValue={system?.artifact_limit_mb ?? 512} min={1} max={10240} />
        </div>
        <input className="input-shell" name="report_defaults" defaultValue={(system?.report_defaults ?? ["json", "md", "sarif", "pdf"]).join(",")} />
        <button className="button primary" type="submit">Save system</button>
      </form>

      <form className="stat-panel" action={saveProject}>
        <h2>Project Settings</h2>
        <input type="hidden" name="project_id" value={project?.id ?? ""} />
        <input className="input-shell" name="target_url" defaultValue={projectSettings?.target_url ?? project?.target_url ?? ""} disabled={!project} />
        <input className="input-shell" name="approved_hosts" defaultValue={(projectSettings?.approved_hosts ?? []).join(",")} disabled={!project} />
        <input className="input-shell" name="excluded_paths" defaultValue={(projectSettings?.excluded_paths ?? []).join(",")} disabled={!project} />
        <select className="select-shell" name="scan_depth" defaultValue={projectSettings?.scan_depth ?? "full"} disabled={!project}>
          <option value="quick">Quick</option>
          <option value="full">Full</option>
          <option value="deep">Deep</option>
        </select>
        <label className="checkbox-line">
          <input name="authorization_confirmed" type="checkbox" defaultChecked={projectSettings?.authorization_confirmed ?? false} disabled={!project} />
          <span>Authorization confirmed</span>
        </label>
        <input className="input-shell" name="test_identity_label" placeholder="Test identity label" disabled={!project} />
        <input className="input-shell" name="test_identity_username" placeholder="Test identity username" disabled={!project} />
        <input className="input-shell" name="test_identity_password" type="password" placeholder={projectSettings?.test_identities_configured ? "Configured; enter to rotate" : "Password"} disabled={!project} />
        <button className="button primary" type="submit" disabled={!project}>Save project</button>
        {!project ? <p className="muted">Create a project before saving project settings.</p> : null}
      </form>

      <form className="stat-panel" action={saveGitHub}>
        <h2>GitHub Contracts</h2>
        <p className="muted">{github?.message ?? "GitHub private access is blocked until credentials are supplied."}</p>
        <input className="input-shell" name="app_id" placeholder="GitHub App ID" />
        <input className="input-shell" name="client_id" placeholder="OAuth client ID" />
        <input className="input-shell" name="client_secret" type="password" placeholder={github?.credential_state?.client_secret ? "Client secret configured; enter to rotate" : "OAuth client secret"} />
        <input className="input-shell" name="private_key" type="password" placeholder={github?.credential_state?.private_key ? "Private key configured; enter to rotate" : "Private key"} />
        <input className="input-shell" name="webhook_secret" type="password" placeholder={github?.credential_state?.webhook_secret ? "Webhook secret configured; enter to rotate" : "Webhook secret"} />
        <input className="input-shell" name="callback_url" defaultValue={github?.callback_url ?? ""} placeholder="http://localhost:8000/api/github/callback" />
        <input className="input-shell" name="selected_repository" defaultValue={github?.selected_repository ?? ""} placeholder="owner/repo" />
        <input className="input-shell" name="selected_branch" defaultValue={github?.selected_branch ?? ""} placeholder="main" />
        <button className="button primary" type="submit">Save GitHub contract</button>
        <span className="severity-pill severity-info">{github?.status ?? "blocked_missing_credentials"}</span>
      </form>
    </div>
  );
}
