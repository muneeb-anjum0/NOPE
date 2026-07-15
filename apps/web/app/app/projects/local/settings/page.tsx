import { getAIHealth, getModelSettings } from "@/lib/nope-data";

export default async function SettingsPage() {
  const model = await getModelSettings();
  const aiHealth = await getAIHealth();
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
        ["Dynamic tests", "Runtime checks are recorded as coverage gaps until configured.", "Partial"],
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
    </>
  );
}
