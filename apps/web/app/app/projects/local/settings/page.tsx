import { getModelSettings } from "@/lib/nope-data";

export default async function SettingsPage() {
  const model = await getModelSettings();
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Settings</p>
          <h1>Local policy, scanner, and Qwen controls.</h1>
          <p>Qwen is a reasoning service. It gets focused evidence, not shell access.</p>
        </div>
      </section>
      <div className="app-grid cols-3">
        <div className="app-panel">
          <span className="mono muted">model provider</span>
          <h2>{model?.provider ?? "unknown"}</h2>
          <p className="muted">{model?.runtime_endpoint ?? "API unavailable"}</p>
        </div>
        <div className="app-panel">
          <span className="mono muted">model</span>
          <h2>{model?.model_name ?? "not configured"}</h2>
          <p className="muted">Context {model?.context_length ?? 0} / output {model?.maximum_output_tokens ?? 0}</p>
        </div>
        <div className="app-panel">
          <span className="mono muted">GPU target</span>
          <h2>{model?.gpu_layer_count ?? 0} layers</h2>
          <p className="muted">{model?.maximum_gpu_memory_target_mb ?? 0} MB target</p>
        </div>
      </div>
    </>
  );
}
