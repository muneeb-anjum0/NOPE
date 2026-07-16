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
    <div className="settings-form-list">
      <details className="collapse-panel settings-accordion compact-settings" name="editable-settings">
        <summary>
          <span><h2>System</h2></span>
          <span className="mono muted">12 fields</span>
        </summary>
        <form className="collapse-body editable-settings-list" action={saveSystem}>
          <label className="settings-edit-row">
            <span><strong>Qwen endpoint</strong></span>
            <input className="input-shell" name="qwen_endpoint" defaultValue={system?.qwen_endpoint ?? "http://nope-ai:8080"} placeholder="e.g. http://nope-ai:8080" />
          </label>
          <label className="settings-edit-row">
            <span><strong>Runtime</strong></span>
            <select className="select-shell" name="runtime" defaultValue={system?.runtime ?? "llama.cpp"}>
              <option value="llama.cpp">llama.cpp</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label className="settings-edit-row">
            <span><strong>Context</strong></span>
            <input className="input-shell" name="context" type="number" defaultValue={system?.context ?? 4096} placeholder="e.g. 4096" min={512} max={32768} />
          </label>
          <label className="settings-edit-row">
            <span><strong>GPU layers</strong></span>
            <input className="input-shell" name="gpu_layers" type="number" defaultValue={system?.gpu_layers ?? 28} placeholder="e.g. 28" min={0} max={128} />
          </label>
          <label className="settings-edit-row">
            <span><strong>AI timeout</strong></span>
            <input className="input-shell" name="timeout" type="number" defaultValue={system?.timeout ?? 180} placeholder="e.g. 180" min={5} max={1800} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Output limit</strong></span>
            <input className="input-shell" name="output_limit" type="number" defaultValue={system?.output_limit ?? 1024} placeholder="e.g. 1024" min={64} max={8192} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Concurrency</strong></span>
            <input className="input-shell" name="concurrency" type="number" defaultValue={system?.concurrency ?? 1} placeholder="e.g. 1" min={1} max={8} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Scanner timeout</strong></span>
            <input className="input-shell" name="scanner_timeout" type="number" defaultValue={system?.scanner_timeout ?? 180} placeholder="e.g. 180" min={5} max={3600} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Scan mode</strong></span>
            <select className="select-shell" name="default_scan_mode" defaultValue={system?.default_scan_mode ?? "full"}>
              <option value="full">Full</option>
              <option value="repository">Repository</option>
              <option value="url">URL</option>
            </select>
          </label>
          <label className="settings-edit-row">
            <span><strong>Retention</strong></span>
            <input className="input-shell" name="retention_days" type="number" defaultValue={system?.retention_days ?? 30} placeholder="e.g. 30" min={1} max={3650} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Artifact MB</strong></span>
            <input className="input-shell" name="artifact_limit_mb" type="number" defaultValue={system?.artifact_limit_mb ?? 512} placeholder="e.g. 512" min={1} max={10240} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Reports</strong></span>
            <input className="input-shell" name="report_defaults" defaultValue={(system?.report_defaults ?? ["json", "md", "sarif", "pdf"]).join(",")} placeholder="e.g. json,md,sarif,pdf" />
          </label>
          <div className="settings-edit-actions">
            <button className="button primary" type="submit">Save</button>
          </div>
        </form>
      </details>

      <details className="collapse-panel settings-accordion compact-settings" name="editable-settings">
        <summary>
          <span><h2>Project</h2></span>
          <span className="mono muted">{project ? "editable" : "no project"}</span>
        </summary>
        <form className="collapse-body editable-settings-list" action={saveProject}>
          <input type="hidden" name="project_id" value={project?.id ?? ""} />
          <label className="settings-edit-row">
            <span><strong>Target URL</strong></span>
            <input className="input-shell" name="target_url" defaultValue={projectSettings?.target_url ?? project?.target_url ?? ""} placeholder="e.g. https://app.example.com" disabled={!project} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Hosts</strong></span>
            <input className="input-shell" name="approved_hosts" defaultValue={(projectSettings?.approved_hosts ?? []).join(",")} placeholder="e.g. app.example.com, api.example.com" disabled={!project} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Exclude</strong></span>
            <input className="input-shell" name="excluded_paths" defaultValue={(projectSettings?.excluded_paths ?? []).join(",")} placeholder="e.g. /admin/debug, /internal" disabled={!project} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Depth</strong></span>
            <select className="select-shell" name="scan_depth" defaultValue={projectSettings?.scan_depth ?? "full"} disabled={!project}>
              <option value="quick">Quick</option>
              <option value="full">Full</option>
              <option value="deep">Deep</option>
            </select>
          </label>
          <label className="settings-edit-row">
            <span><strong>Authorized</strong></span>
            <span className="settings-inline-control">
              <input name="authorization_confirmed" type="checkbox" defaultChecked={projectSettings?.authorization_confirmed ?? false} disabled={!project} />
              <span className="muted">Confirmed</span>
            </span>
          </label>
          <label className="settings-edit-row">
            <span><strong>Test label</strong></span>
            <input className="input-shell" name="test_identity_label" placeholder="e.g. ghost tester" disabled={!project} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Test user</strong></span>
            <input className="input-shell" name="test_identity_username" placeholder="e.g. ghost@example.com" disabled={!project} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Test password</strong></span>
            <input className="input-shell" name="test_identity_password" type="password" placeholder={projectSettings?.test_identities_configured ? "configured; enter to rotate" : "e.g. ghost-test-password"} disabled={!project} />
          </label>
          <div className="settings-edit-actions">
            {!project ? <span className="muted">Create a project first.</span> : null}
            <button className="button primary" type="submit" disabled={!project}>Save</button>
          </div>
        </form>
      </details>

      <details className="collapse-panel settings-accordion compact-settings" name="editable-settings">
        <summary>
          <span><h2>GitHub</h2></span>
          <span className="mono muted">{github?.status ?? "blocked"}</span>
        </summary>
        <form className="collapse-body editable-settings-list" action={saveGitHub}>
          <label className="settings-edit-row">
            <span><strong>App ID</strong></span>
            <input className="input-shell" name="app_id" placeholder="e.g. 123456" />
          </label>
          <label className="settings-edit-row">
            <span><strong>Client ID</strong></span>
            <input className="input-shell" name="client_id" placeholder="e.g. Iv1.xxxxx" />
          </label>
          <label className="settings-edit-row">
            <span><strong>Client secret</strong></span>
            <input className="input-shell" name="client_secret" type="password" placeholder={github?.credential_state?.client_secret ? "configured; enter to rotate" : "e.g. github_oauth_secret"} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Private key</strong></span>
            <input className="input-shell" name="private_key" type="password" placeholder={github?.credential_state?.private_key ? "configured; enter to rotate" : "paste PEM private key"} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Webhook</strong></span>
            <input className="input-shell" name="webhook_secret" type="password" placeholder={github?.credential_state?.webhook_secret ? "configured; enter to rotate" : "e.g. webhook-secret"} />
          </label>
          <label className="settings-edit-row">
            <span><strong>Callback</strong></span>
            <input className="input-shell" name="callback_url" defaultValue={github?.callback_url ?? ""} placeholder="e.g. http://localhost:8000/api/github/callback" />
          </label>
          <label className="settings-edit-row">
            <span><strong>Repository</strong></span>
            <input className="input-shell" name="selected_repository" defaultValue={github?.selected_repository ?? ""} placeholder="e.g. owner/repo" />
          </label>
          <label className="settings-edit-row">
            <span><strong>Branch</strong></span>
            <input className="input-shell" name="selected_branch" defaultValue={github?.selected_branch ?? ""} placeholder="e.g. main" />
          </label>
          <div className="settings-edit-actions">
            <span className="severity-pill severity-info">{github?.status ?? "blocked_missing_credentials"}</span>
            <button className="button primary" type="submit">Save</button>
          </div>
        </form>
      </details>
    </div>
  );
}
