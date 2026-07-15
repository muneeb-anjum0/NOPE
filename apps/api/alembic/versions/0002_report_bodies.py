from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0002_report_bodies"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _sql_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / "migrations" / name).read_text(encoding="utf-8")


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_sql_file("0002_report_bodies.sql"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql("drop index if exists idx_reports_scan_created")
    bind.exec_driver_sql("alter table reports drop column if exists generated_at")
    bind.exec_driver_sql("alter table reports drop column if exists byte_size")
    bind.exec_driver_sql("alter table reports drop column if exists body_sha256")
    bind.exec_driver_sql("alter table reports drop column if exists body")
