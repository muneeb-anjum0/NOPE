from __future__ import annotations

from hashlib import sha256
from typing import Any

from psycopg.types.json import Jsonb

from nope_api.artifacts import put_json_artifact
from nope_api.config import get_settings
from nope_api.db import connect, run_migrations
from nope_api.models import Project, Scan, new_id
from nope_api.reports import render_report


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

    def get_report(
        self,
        scan_id: str,
        fmt: str,
        owner_user_id: str | None = None,
    ) -> tuple[str, str] | None:
        self.migrate()
        query = """
            select reports.media_type, reports.body
            from reports
            join scans on scans.id = reports.scan_id
            where reports.scan_id = %s and reports.format = %s
        """
        params: tuple[Any, ...] = (scan_id, fmt)
        if owner_user_id:
            query += " and scans.owner_user_id = %s"
            params = (scan_id, fmt, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        if not row or not row["body"]:
            return None
        return str(row["media_type"]), str(row["body"])

    def backfill_report_bodies(self) -> int:
        self.migrate()
        updated = 0
        with connect(self.settings) as conn:
            rows = conn.execute(
                """
                select reports.id, reports.format, scans.data
                from reports
                join scans on scans.id = reports.scan_id
                where reports.body = ''
                """
            ).fetchall()
            for row in rows:
                try:
                    scan = Scan(**row["data"])
                    media_type, body = render_report(scan, str(row["format"]))
                except ValueError:
                    continue
                encoded = body.encode("utf-8")
                body_sha256 = sha256(encoded).hexdigest()
                conn.execute(
                    """
                    update reports
                    set media_type = %s,
                        body = %s,
                        body_sha256 = %s,
                        byte_size = %s,
                        generated_at = now(),
                        data = data || %s
                    where id = %s
                    """,
                    (
                        media_type,
                        body,
                        body_sha256,
                        len(encoded),
                        Jsonb({"body_sha256": body_sha256, "byte_size": len(encoded)}),
                        row["id"],
                    ),
                )
                updated += 1
        return updated

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
            artifact = self._store_scanner_artifact(scan.id, run)
            if artifact:
                run.raw_artifact_id = artifact["id"]
                run.raw_artifact_url = artifact["storage_url"]
            conn.execute(
                """
                insert into scanner_runs (
                  scan_id, scanner, version, status, coverage_categories,
                  started_at, completed_at, message, findings_count, raw_artifact_id, data
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    run.raw_artifact_id,
                    Jsonb(run.model_dump(mode="json")),
                ),
            )
            if artifact:
                conn.execute(
                    """
                    insert into uploaded_artifacts (
                      id, scan_id, artifact_type, filename, storage_url, size_bytes, sha256, data
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (id) do nothing
                    """,
                    (
                        artifact["id"],
                        scan.id,
                        artifact["type"],
                        artifact["filename"],
                        artifact["storage_url"],
                        artifact["size_bytes"],
                        artifact["sha256"],
                        Jsonb(artifact),
                    ),
                )
                conn.execute(
                    """
                    insert into job_artifacts (id, scan_id, artifact_type, storage_url, data)
                    values (%s, %s, %s, %s, %s)
                    on conflict (id) do nothing
                    """,
                    (
                        f"job_{artifact['id']}",
                        scan.id,
                        artifact["type"],
                        artifact["storage_url"],
                        Jsonb(artifact),
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
            media_type, body = render_report(scan, fmt)
            encoded = body.encode("utf-8")
            body_sha256 = sha256(encoded).hexdigest()
            conn.execute(
                """
                insert into reports (
                  id, scan_id, format, media_type, body, body_sha256, byte_size, generated_at, data
                )
                values (%s, %s, %s, %s, %s, %s, %s, now(), %s)
                on conflict (scan_id, format) do update set
                  media_type = excluded.media_type,
                  body = excluded.body,
                  body_sha256 = excluded.body_sha256,
                  byte_size = excluded.byte_size,
                  generated_at = excluded.generated_at,
                  data = excluded.data
                """,
                (
                    f"rpt_{scan.id}_{fmt}",
                    scan.id,
                    fmt,
                    media_type or REPORT_MEDIA_TYPES.get(fmt, "application/octet-stream"),
                    body,
                    body_sha256,
                    len(encoded),
                    Jsonb(
                        {
                            "scan_id": scan.id,
                            "format": fmt,
                            "body_sha256": body_sha256,
                            "byte_size": len(encoded),
                        }
                    ),
                ),
            )

    def _store_scanner_artifact(self, scan_id: str, run) -> dict | None:
        if not run.raw_stdout and not run.raw_stderr:
            return None
        safe_name = "".join(ch.lower() if ch.isalnum() else "-" for ch in run.scanner).strip("-")
        return put_json_artifact(
            self.settings,
            scan_id=scan_id,
            artifact_type="scanner_raw_output",
            name=f"{safe_name}-raw-output",
            payload={
                "scan_id": scan_id,
                "scanner": run.scanner,
                "command": run.command,
                "exit_code": run.exit_code,
                "status": run.status,
                "stdout": run.raw_stdout,
                "stderr": run.raw_stderr,
            },
        )


store = PostgresStore()
