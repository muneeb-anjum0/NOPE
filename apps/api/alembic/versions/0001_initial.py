from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def _sql_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / "migrations" / name).read_text(encoding="utf-8")


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_sql_file("0001_initial.sql"))


def downgrade() -> None:
    bind = op.get_bind()
    for table in [
        "github_repository_references",
        "github_installations",
        "github_connections",
        "audit_logs",
        "job_artifacts",
        "uploaded_artifacts",
        "drift_events",
        "security_baselines",
        "application_settings",
        "scanner_configurations",
        "model_configurations",
        "reports",
        "scan_coverage",
        "finding_history",
        "finding_sources",
        "finding_evidence",
        "findings",
        "scanner_runs",
        "scan_events",
        "scan_stages",
        "scans",
        "repository_snapshots",
        "repository_sources",
        "project_targets",
        "projects",
        "local_sessions",
        "local_users",
    ]:
        bind.exec_driver_sql(f"drop table if exists {table} cascade")
