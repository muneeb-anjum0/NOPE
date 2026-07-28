"""Stage 14 repository intelligence tables."""

from pathlib import Path

from alembic import op


revision = "0007_repository_intelligence"
down_revision = "0006_rules_v2_normalized"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sql_path = Path(__file__).resolve().parents[2] / "migrations" / "0007_repository_intelligence.sql"
    op.execute(sql_path.read_text(encoding="utf-8"))


def downgrade() -> None:
    op.execute("drop table if exists repository_index_failures cascade")
    op.execute("drop table if exists repository_retrieval_results cascade")
    op.execute("drop table if exists repository_retrieval_sessions cascade")
    op.execute("drop table if exists repository_indexed_chunks cascade")
    op.execute("drop table if exists repository_indexed_files cascade")
    op.execute("drop table if exists repository_indexes cascade")
