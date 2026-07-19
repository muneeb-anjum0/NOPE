from __future__ import annotations

from pathlib import Path

from alembic import op

revision = "0006_rules_v2_normalized"
down_revision = "0005_ai_actions"
branch_labels = None
depends_on = None


def _sql_file(name: str) -> str:
    return (Path(__file__).resolve().parents[2] / "migrations" / name).read_text(encoding="utf-8")


def upgrade() -> None:
    op.get_bind().exec_driver_sql(_sql_file("0006_rules_v2_normalized.sql"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql("drop index if exists idx_rules_v2_suppressions_active")
    bind.exec_driver_sql("drop index if exists idx_rules_v2_history_scan_result")
    bind.exec_driver_sql("drop index if exists idx_rules_v2_correlations_candidate")
    bind.exec_driver_sql("drop index if exists idx_rules_v2_evidence_candidate")
    bind.exec_driver_sql("drop index if exists idx_rules_v2_candidates_project_rule")
    bind.exec_driver_sql("drop index if exists idx_rules_v2_candidates_scan_file")
    bind.exec_driver_sql("drop index if exists idx_rules_v2_candidates_scan_result")
    bind.exec_driver_sql("drop table if exists rules_v2_candidate_suppressions cascade")
    bind.exec_driver_sql("drop table if exists rules_v2_promotion_history cascade")
    bind.exec_driver_sql("drop table if exists rules_v2_candidate_correlations cascade")
    bind.exec_driver_sql("drop table if exists rules_v2_candidate_evidence cascade")
    bind.exec_driver_sql("drop table if exists rules_v2_candidates cascade")
