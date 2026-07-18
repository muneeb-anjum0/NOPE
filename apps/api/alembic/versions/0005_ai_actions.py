from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0005_ai_actions"
down_revision = "0004_finding_lifecycle"
branch_labels = None
depends_on = None


def _sql_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / "migrations" / name).read_text(encoding="utf-8")


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_sql_file("0005_ai_actions.sql"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql("drop index if exists idx_ai_action_jobs_scan_finding")
    bind.exec_driver_sql("drop index if exists idx_ai_action_jobs_owner_status")
    bind.exec_driver_sql("drop index if exists idx_ai_action_cache_fingerprint_action")
    bind.exec_driver_sql("drop index if exists idx_ai_action_cache_owner_expiry")
    bind.exec_driver_sql("drop table if exists ai_action_jobs cascade")
    bind.exec_driver_sql("drop table if exists ai_action_cache cascade")
