from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0004_finding_lifecycle"
down_revision = "0003_scan_events"
branch_labels = None
depends_on = None


def _sql_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / "migrations" / name).read_text(encoding="utf-8")


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_sql_file("0004_finding_lifecycle.sql"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql("drop table if exists finding_lifecycle_events cascade")
    bind.exec_driver_sql("drop index if exists idx_findings_project_fingerprint")
    bind.exec_driver_sql("drop index if exists idx_findings_scan_status")
    bind.exec_driver_sql("drop index if exists idx_findings_suppressed_until")
    bind.exec_driver_sql("alter table findings drop column if exists status_version")
    bind.exec_driver_sql("alter table findings drop column if exists suppressed_until")
    bind.exec_driver_sql("alter table findings drop column if exists suppression_scope")
    bind.exec_driver_sql("alter table findings drop column if exists suppression_reason")
    bind.exec_driver_sql("alter table findings drop column if exists suppression_actor")
