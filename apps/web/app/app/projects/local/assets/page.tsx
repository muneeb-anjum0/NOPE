export default function AssetsPage() {
  return (
    <>
      <section className="page-header">
        <div>
          <p className="section-kicker">Assets</p>
          <h1>Inventory the exposed surface.</h1>
          <p>Routes, frameworks, storage, external calls, scanners, targets, commits, and runtime gaps.</p>
        </div>
      </section>
      <div className="app-grid cols-3">
        {["Routes", "Data systems", "Object storage", "External calls", "CI/CD", "AI APIs"].map((asset) => (
          <div className="app-panel" key={asset}>
            <span className="mono muted">asset class</span>
            <h2>{asset}</h2>
            <p className="muted">Populated from repository and URL scan evidence.</p>
          </div>
        ))}
      </div>
    </>
  );
}
