from __future__ import annotations

from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from nope_api.config import Settings


def psycopg_url(settings: Settings) -> str:
    if settings.auth_database_url:
        return settings.auth_database_url
    return settings.database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def connect(settings: Settings):
    return psycopg.connect(psycopg_url(settings), row_factory=dict_row)


def migrations_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "migrations"


def migration_status(settings: Settings) -> dict[str, list[str]]:
    available = [path.stem for path in sorted(migrations_dir().glob("*.sql"))]
    with connect(settings) as conn:
        conn.execute(
            """
            create table if not exists schema_migrations (
              version text primary key,
              applied_at timestamptz not null default now()
            )
            """
        )
        applied = [
            row["version"]
            for row in conn.execute("select version from schema_migrations order by version").fetchall()
        ]
    pending = [version for version in available if version not in set(applied)]
    unexpected = [version for version in applied if version not in set(available)]
    return {"available": available, "applied": applied, "pending": pending, "unexpected": unexpected}


def run_migrations(settings: Settings) -> list[str]:
    applied: list[str] = []
    with connect(settings) as conn:
        conn.execute(
            """
            create table if not exists schema_migrations (
              version text primary key,
              applied_at timestamptz not null default now()
            )
            """
        )
        existing = {
            row["version"]
            for row in conn.execute("select version from schema_migrations").fetchall()
        }
        for path in sorted(migrations_dir().glob("*.sql")):
            version = path.stem
            if version in existing:
                continue
            conn.execute(path.read_text(encoding="utf-8"))
            conn.execute("insert into schema_migrations (version) values (%s)", (version,))
            applied.append(version)
    return applied
