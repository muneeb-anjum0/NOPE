import { revalidatePath } from "next/cache";
import { SettingsForms } from "@/components/settings-forms";
import { api } from "@/lib/api";
import { getAIHealth, getGitHubStatus, getModelSettings, getProjectSettings, getProjects, getSystemSettings } from "@/lib/nope-data";

export default async function SettingsPage() {
  const model = await getModelSettings();
  const aiHealth = await getAIHealth();
  const system = await getSystemSettings();
  const projects = await getProjects();
  const project = projects[0] ?? null;
  const projectSettings = project ? await getProjectSettings(project.id) : null;
  const github = await getGitHubStatus();

  async function saveSystem(formData: FormData) {
    "use server";
    await api("/api/settings/system", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        qwen_endpoint: String(formData.get("qwen_endpoint") ?? ""),
        runtime: String(formData.get("runtime") ?? "llama.cpp"),
        context: Number(formData.get("context") ?? 4096),
        gpu_layers: Number(formData.get("gpu_layers") ?? 28),
        timeout: Number(formData.get("timeout") ?? 180),
        output_limit: Number(formData.get("output_limit") ?? 1024),
        concurrency: Number(formData.get("concurrency") ?? 1),
        scanner_enabled: {},
        scanner_timeout: Number(formData.get("scanner_timeout") ?? 180),
        default_scan_mode: String(formData.get("default_scan_mode") ?? "full"),
        retention_days: Number(formData.get("retention_days") ?? 30),
        report_defaults: String(formData.get("report_defaults") ?? "json,md,sarif,pdf").split(",").map((item) => item.trim()).filter(Boolean),
        artifact_limit_mb: Number(formData.get("artifact_limit_mb") ?? 512),
        sandbox_limits: {},
      }),
    });
    revalidatePath("/app/projects/local/settings");
  }

  async function saveProject(formData: FormData) {
    "use server";
    const projectId = String(formData.get("project_id") ?? "");
    if (!projectId) {
      return;
    }
    const password = String(formData.get("test_identity_password") ?? "");
    const identityLabel = String(formData.get("test_identity_label") ?? "");
    const identityUsername = String(formData.get("test_identity_username") ?? "");
    await api(`/api/projects/${projectId}/settings`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        project_id: projectId,
        target_url: String(formData.get("target_url") ?? "") || null,
        approved_hosts: String(formData.get("approved_hosts") ?? "").split(",").map((item) => item.trim()).filter(Boolean),
        excluded_paths: String(formData.get("excluded_paths") ?? "").split(",").map((item) => item.trim()).filter(Boolean),
        scanner_overrides: {},
        scan_depth: String(formData.get("scan_depth") ?? "full"),
        test_identities: identityLabel || identityUsername || password ? [{ label: identityLabel || "Local test identity", username: identityUsername || null, password: password || null }] : [],
        baseline_id: null,
        repository_metadata: {},
        authorization_confirmed: formData.get("authorization_confirmed") === "on",
        rag_limits: {},
      }),
    });
    revalidatePath("/app/projects/local/settings");
  }

  async function saveGitHub(formData: FormData) {
    "use server";
    await api("/api/github/settings", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        app_id: String(formData.get("app_id") ?? "") || null,
        client_id: String(formData.get("client_id") ?? "") || null,
        client_secret: String(formData.get("client_secret") ?? "") || null,
        private_key: String(formData.get("private_key") ?? "") || null,
        webhook_secret: String(formData.get("webhook_secret") ?? "") || null,
        callback_url: String(formData.get("callback_url") ?? "") || null,
        selected_repository: String(formData.get("selected_repository") ?? "") || null,
        selected_branch: String(formData.get("selected_branch") ?? "") || null,
      }),
    });
    revalidatePath("/app/projects/local/settings");
  }

  const sections = [
    {
      title: "Workspace",
      summary: "Local project identity and dashboard isolation.",
      rows: [
        ["Project", "Each login lands in its own local NOPE workspace shell.", "Local"],
        ["Session", "HttpOnly cookie backed by Postgres session records.", "Enabled"],
        ["Reports", "Exports use the latest scan available to the local workspace.", "Ready"],
      ],
    },
    {
      title: "Scanning Policy",
      summary: "Safety rails for repository and deployed URL scans.",
      rows: [
        ["URL scope", "Private and localhost targets remain blocked unless explicitly allowed.", "Strict"],
        ["Repository input", "Zip uploads are extracted into NOPE workspaces for analysis.", "Scoped"],
        ["Dynamic tests", "Sandbox manifests can run constrained workflows and internal ZAP.", "Sandbox"],
      ],
    },
    {
      title: "Qwen Reasoning",
      summary: "Local model settings for focused evidence review.",
      rows: [
        ["Provider", model?.provider ?? "API unavailable", "Model"],
        ["Model", model?.model_name ?? "not configured", "Runtime"],
        ["Endpoint", model?.runtime_endpoint ?? "not configured", "Local"],
        ["Context", `${model?.context_length ?? 0} context / ${model?.maximum_output_tokens ?? 0} output`, "Limit"],
        ["GPU target", `${model?.gpu_layer_count ?? 0} layers / ${model?.maximum_gpu_memory_target_mb ?? 0} MB`, "Budget"],
        ["GPU state", aiHealth?.gpu?.status ?? "unknown", aiHealth?.gpu?.layers ? `${aiHealth.gpu.layers} layers` : "State"],
        ["Latency", aiHealth?.latency_ms ? `${aiHealth.latency_ms} ms` : aiHealth?.status ?? "unverified", "Health"],
        ["Concurrency", `${model?.parallel ?? 0} parallel / batch ${model?.batch_size ?? 0}`, "Bounded"],
        ["RAG limits", `${model?.rag?.maximum_files ?? 0} files / ${model?.rag?.maximum_tokens ?? 0} tokens`, "Focused"],
      ],
    },
    {
      title: "GitHub",
      summary: "Local contracts without fake private repository access.",
      rows: [
        ["Credential state", github?.status ?? "blocked_missing_credentials", "Blocked"],
        ["Callback", github?.callback_url ?? "not configured", "Route"],
        ["Repository", github?.selected_repository ?? "not selected", "Contract"],
      ],
    },
    {
      title: "Data Retention",
      summary: "Where local credentials and evidence live during development.",
      rows: [
        ["Auth database", "Local users and sessions are stored in Postgres.", "Postgres"],
        ["Artifacts", "Reports and evidence can be stored through MinIO.", "MinIO"],
        ["Queue", "Worker jobs use Redis for local coordination.", "Redis"],
      ],
    },
  ];

  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Settings</p>
          <h1>Local policy, scanner, and Qwen controls.</h1>
          <p>Qwen is a reasoning service. It gets focused evidence, not shell access.</p>
        </div>
      </section>
      <div className="collapse-list">
        {sections.map((section, index) => (
          <details className="collapse-panel" key={section.title} open={index < 2}>
            <summary>
              <span>
                <h2>{section.title}</h2>
                <p>{section.summary}</p>
              </span>
              <span className="mono muted">{section.rows.length} settings</span>
            </summary>
            <div className="collapse-body">
              {section.rows.map(([name, detail, status]) => (
                <div className="collapse-row" key={name}>
                  <strong>{name}</strong>
                  <span className="muted">{detail}</span>
                  <span className="severity-pill severity-info">{status}</span>
                </div>
              ))}
            </div>
          </details>
        ))}
      </div>
      <SettingsForms
        system={system}
        project={project}
        projectSettings={projectSettings}
        github={github}
        saveSystem={saveSystem}
        saveProject={saveProject}
        saveGitHub={saveGitHub}
      />
    </>
  );
}
