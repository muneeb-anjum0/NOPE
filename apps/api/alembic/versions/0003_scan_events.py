from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0003_scan_events"
down_revision = "0002_report_bodies"
branch_labels = None
depends_on = None


def _sql_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / "migrations" / name).read_text(encoding="utf-8")


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_sql_file("0003_scan_events.sql"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql("drop table if exists scan_events cascade")
