from __future__ import annotations

from typing import Any

from psycopg.types.json import Jsonb

from nope_api.config import get_settings
from nope_api.db import connect, run_migrations
from nope_api.models import Project, Scan, new_id


REPORT_MEDIA_TYPES = {
    "json": "application/json",
    "md": "text/markdown",
    "sarif": "application/sarif+json",
}


class PostgresStore:
    def __init__(self) -> None:
        self.settings = get_settings()

    def migrate(self) -> list[str]:
        return run_migrations(self.settings)

    def list_projects(self, owner_user_id: str | None = None) -> list[Project]:
        self.migrate()
        query = "select id, name, repository, target_url, created_at from projects"
        params: tuple[Any, ...] = ()
        if owner_user_id:
            query += " where owner_user_id = %s"
            params = (owner_user_id,)
        query += " order by created_at desc"
        with connect(self.settings) as conn:
            rows = conn.execute(query, params).fetchall()
        if not rows and owner_user_id is None:
            return [
                Project(
                    id="prj_demo",
                    name="NOPE Local Demo",
                    repository="Uploaded ZIP",
                    target_url="https://example.com",
                )
            ]
        return [Project(**dict(row)) for row in rows]

    def create_project(
        self,
        name: str,
        repository: str | None,
        target_url: str | None,
        owner_user_id: str | None = None,
    ) -> Project:
        self.migrate()
        project = Project(id=new_id("prj"), name=name, repository=repository, target_url=target_url)
        with connect(self.settings) as conn:
            conn.execute(
                """
                insert into projects (id, owner_user_id, name, repository, target_url, created_at)
                values (%s, %s, %s, %s, %s, %s)
                """,
                (project.id, owner_user_id, project.name, project.repository, project.target_url, project.created_at),
            )
        return project

    def save_scan(self, scan: Scan, owner_user_id: str | None = None) -> Scan:
        self.migrate()
        data = scan.model_dump(mode="json")
        with connect(self.settings) as conn:
            conn.execute(
                """
                insert into scans (
                  id, owner_user_id, project_id, mode, status, verdict, score, coverage_percent,
                  target_url, repository_name, branch, commit_sha, started_at, completed_at, data
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (id) do update set
                  owner_user_id = coalesce(scans.owner_user_id, excluded.owner_user_id),
                  project_id = excluded.project_id,
                  mode = excluded.mode,
                  status = excluded.status,
                  verdict = excluded.verdict,
                  score = excluded.score,
                  coverage_percent = excluded.coverage_percent,
                  target_url = excluded.target_url,
                  repository_name = excluded.repository_name,
                  branch = excluded.branch,
                  commit_sha = excluded.commit_sha,
                  started_at = excluded.started_at,
                  completed_at = excluded.completed_at,
                  data = excluded.data
                """,
                (
                    scan.id,
                    owner_user_id,
                    scan.project_id,
                    scan.mode.value,
                    scan.status,
                    scan.verdict,
                    scan.score,
                    scan.coverage_percent,
                    scan.target_url,
                    scan.repository_name,
                    scan.branch,
                    scan.commit_sha,
                    scan.started_at,
                    scan.completed_at,
                    Jsonb(data),
                ),
            )
            self._replace_scan_children(conn, scan)
        return scan

    def get_scan(self, scan_id: str, owner_user_id: str | None = None) -> Scan | None:
        self.migrate()
        query = "select data from scans where id = %s"
        params: tuple[Any, ...] = (scan_id,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (scan_id, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return Scan(**row["data"]) if row else None

    def list_scans(self, owner_user_id: str | None = None) -> list[Scan]:
        self.migrate()
        query = "select data from scans"
        params: tuple[Any, ...] = ()
        if owner_user_id:
            query += " where owner_user_id = %s"
            params = (owner_user_id,)
        query += " order by started_at desc"
        with connect(self.settings) as conn:
            rows = conn.execute(query, params).fetchall()
        return [Scan(**row["data"]) for row in rows]

    def user_owns_scan(self, scan_id: str, owner_user_id: str) -> bool:
        self.migrate()
        with connect(self.settings) as conn:
            row = conn.execute(
                "select 1 from scans where id = %s and owner_user_id = %s",
                (scan_id, owner_user_id),
            ).fetchone()
        return row is not None

    def _replace_scan_children(self, conn, scan: Scan) -> None:
        conn.execute("delete from reports where scan_id = %s", (scan.id,))
        conn.execute("delete from scan_coverage where scan_id = %s", (scan.id,))
        conn.execute("delete from scanner_runs where scan_id = %s", (scan.id,))
        conn.execute("delete from scan_stages where scan_id = %s", (scan.id,))
        conn.execute("delete from findings where scan_id = %s", (scan.id,))

        for index, stage in enumerate(scan.stages):
            conn.execute(
                """
                insert into scan_stages (scan_id, position, name, status, message, data)
                values (%s, %s, %s, %s, %s, %s)
                """,
                (
                    scan.id,
                    index,
                    str(stage.get("name", f"Stage {index + 1}")),
                    str(stage.get("status", "pending")),
                    stage.get("message"),
                    Jsonb(stage),
                ),
            )

        for run in scan.scanner_runs:
            conn.execute(
                """
                insert into scanner_runs (
                  scan_id, scanner, version, status, coverage_categories,
                  started_at, completed_at, message, findings_count, data
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    scan.id,
                    run.scanner,
                    run.version,
                    run.status,
                    Jsonb(run.coverage_categories),
                    run.started_at,
                    run.completed_at,
                    run.message,
                    run.findings_count,
                    Jsonb(run.model_dump(mode="json")),
                ),
            )

        for finding in scan.findings:
            finding_data = finding.model_dump(mode="json")
            conn.execute(
                """
                insert into findings (
                  id, scan_id, project_id, fingerprint, title, description, severity, confidence,
                  category, cwe, owasp, affected_file, affected_route, remediation, status,
                  first_seen, last_seen, fix_available, verified, data
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    finding.id,
                    scan.id,
                    scan.project_id,
                    finding.fingerprint,
                    finding.title,
                    finding.description,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.category,
                    finding.cwe,
                    finding.owasp,
                    finding.affected_file,
                    finding.affected_route,
                    finding.remediation,
                    finding.status,
                    finding.first_seen,
                    finding.last_seen,
                    finding.fix_available,
                    finding.verified,
                    Jsonb(finding_data),
                ),
            )
            conn.execute(
                """
                insert into finding_history (finding_id, fingerprint, scan_id, event, data)
                values (%s, %s, %s, %s, %s)
                """,
                (finding.id, finding.fingerprint, scan.id, "observed", Jsonb({"status": finding.status})),
            )
            for source in finding.scanner_sources:
                conn.execute(
                    "insert into finding_sources (finding_id, scanner_source) values (%s, %s) on conflict do nothing",
                    (finding.id, source),
                )
            for evidence in finding.evidence:
                conn.execute(
                    """
                    insert into finding_evidence (finding_id, source, file, line, route, snippet, message, data)
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        finding.id,
                        evidence.source,
                        evidence.file,
                        evidence.line,
                        evidence.route,
                        evidence.snippet,
                        evidence.message,
                        Jsonb(evidence.model_dump(mode="json")),
                    ),
                )

        for record in scan.coverage:
            conn.execute(
                """
                insert into scan_coverage (scan_id, domain, status, scanners, notes)
                values (%s, %s, %s, %s, %s)
                on conflict (scan_id, domain) do update set
                  status = excluded.status,
                  scanners = excluded.scanners,
                  notes = excluded.notes
                """,
                (scan.id, record.domain, record.status.value, Jsonb(record.scanners), record.notes),
            )

        for fmt in scan.report_formats:
            conn.execute(
                """
                insert into reports (id, scan_id, format, media_type, data)
                values (%s, %s, %s, %s, %s)
                on conflict (scan_id, format) do update set
                  media_type = excluded.media_type,
                  data = excluded.data
                """,
                (
                    f"rpt_{scan.id}_{fmt}",
                    scan.id,
                    fmt,
                    REPORT_MEDIA_TYPES.get(fmt, "application/octet-stream"),
                    Jsonb({"scan_id": scan.id, "format": fmt}),
                ),
            )


store = PostgresStore()
