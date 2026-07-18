from __future__ import annotations

import base64
import re
from hashlib import sha256
from typing import Any

from psycopg.types.json import Jsonb

from nope_api.artifacts import put_binary_artifact, put_json_artifact
from nope_api.config import get_settings
from nope_api.db import connect, run_migrations
from nope_api.lifecycle import LifecycleTransitionRequest, apply_transition
from nope_api.models import BaselineState, FindingStatus, Project, Scan, ScanEvent, now_utc, new_id
from nope_api.reports import render_report


REPORT_MEDIA_TYPES = {
    "json": "application/json",
    "md": "text/markdown",
    "sarif": "application/sarif+json",
    "pdf": "application/pdf",
}

_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|authorization|bearer|sk-[a-z0-9_-]{8,}|ghp_[a-z0-9_]+)\s*[:=]\s*([^\s,'\"]+)"
)


def _redact_event_text(value: str | None, limit: int = 4096) -> str:
    if not value:
        return ""
    redacted = _SECRET_RE.sub(lambda match: f"{match.group(1)}=***REDACTED***", str(value))
    return redacted[:limit]


def _stage_event_type(status: str) -> str:
    return {
        "queued": "stage_queued",
        "running": "stage_started",
        "completed": "stage_completed",
        "partial": "stage_partial",
        "failed": "stage_failed",
        "skipped": "stage_skipped",
        "cancelled": "scan_cancelled",
        "timed out": "stage_failed",
        "timed_out": "stage_failed",
    }.get(status, "stage_progress")


def _scanner_event_type(status: str, message: str = "") -> str:
    lowered = (message or "").lower()
    if "timeout" in lowered or status == "timed_out":
        return "scanner_timed_out"
    if "unavailable" in lowered or status == "skipped":
        return "scanner_unavailable"
    if status == "failed":
        return "scanner_failed"
    return "scanner_completed"


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
            if target_url:
                conn.execute(
                    """
                    insert into project_targets (id, project_id, target_url, approved_hosts, excluded_paths)
                    values (%s, %s, %s, %s, %s)
                    """,
                    (new_id("tgt"), project.id, target_url, Jsonb([]), Jsonb([])),
                )
            if repository:
                conn.execute(
                    """
                    insert into repository_sources (id, project_id, source_type, repository_name)
                    values (%s, %s, %s, %s)
                    """,
                    (new_id("src"), project.id, "uploaded_zip", repository),
                )
        return project

    def create_project_target(
        self,
        project_id: str,
        target_url: str,
        approved_hosts: list[str] | None = None,
        excluded_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        target = {
            "id": new_id("tgt"),
            "project_id": project_id,
            "target_url": target_url,
            "approved_hosts": approved_hosts or [],
            "excluded_paths": excluded_paths or [],
        }
        with connect(self.settings) as conn:
            conn.execute(
                """
                insert into project_targets (id, project_id, target_url, approved_hosts, excluded_paths)
                values (%s, %s, %s, %s, %s)
                """,
                (
                    target["id"],
                    project_id,
                    target_url,
                    Jsonb(target["approved_hosts"]),
                    Jsonb(target["excluded_paths"]),
                ),
            )
        return target

    def create_repository_source(
        self,
        project_id: str,
        source_type: str,
        repository_name: str | None = None,
        url: str | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        source = {
            "id": new_id("src"),
            "project_id": project_id,
            "source_type": source_type,
            "repository_name": repository_name,
            "url": url,
        }
        with connect(self.settings) as conn:
            conn.execute(
                """
                insert into repository_sources (id, project_id, source_type, repository_name, url)
                values (%s, %s, %s, %s, %s)
                """,
                (source["id"], project_id, source_type, repository_name, url),
            )
        return source

    def create_repository_snapshot(
        self,
        project_id: str,
        repository_source_id: str | None = None,
        branch: str | None = None,
        commit_sha: str | None = None,
        upload_name: str | None = None,
        uploaded_artifact_id: str | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        snapshot = {
            "id": new_id("snap"),
            "project_id": project_id,
            "repository_source_id": repository_source_id,
            "branch": branch,
            "commit_sha": commit_sha,
            "upload_name": upload_name,
            "uploaded_artifact_id": uploaded_artifact_id,
        }
        with connect(self.settings) as conn:
            conn.execute(
                """
                insert into repository_snapshots (
                  id, project_id, repository_source_id, branch, commit_sha, upload_name, uploaded_artifact_id
                )
                values (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    snapshot["id"],
                    project_id,
                    repository_source_id,
                    branch,
                    commit_sha,
                    upload_name,
                    uploaded_artifact_id,
                ),
            )
        return snapshot

    def _ensure_deleted_scans_table(self, conn) -> None:
        conn.execute(
            """
            create table if not exists deleted_scans (
              scan_id text primary key,
              owner_user_id text,
              deleted_at timestamptz not null default now()
            )
            """
        )

    def save_scan(self, scan: Scan, owner_user_id: str | None = None) -> Scan:
        self.migrate()
        with connect(self.settings) as conn:
            self._ensure_deleted_scans_table(conn)
            deleted = conn.execute("select 1 from deleted_scans where scan_id = %s", (scan.id,)).fetchone()
            if deleted:
                return scan
            self._prepare_finding_lifecycle(conn, scan)
            data = scan.model_dump(mode="json")
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
            self._upsert_repository_snapshot(conn, scan)
            self._replace_scan_children(conn, scan)
        return scan

    def _prepare_finding_lifecycle(self, conn, scan: Scan) -> None:
        now = now_utc()
        for finding in scan.findings:
            finding.project_id = scan.project_id
            finding.scan_id = scan.id
            finding.lifecycle_version = max(1, int(finding.lifecycle_version or 1))
            if not finding.original_fingerprint:
                finding.original_fingerprint = finding.fingerprint
            if finding.status == "open":
                finding.status = FindingStatus.new.value
            if finding.suppression and finding.suppression.expiry and finding.suppression.expiry <= now:
                finding.suppression_expired_at = now
                finding.suppression = None
                finding.status = FindingStatus.reopened.value
            elif finding.suppression:
                if not finding.suppression.actor:
                    finding.suppression.actor = finding.suppression.user
                finding.status = FindingStatus.suppressed.value
            active_suppression = self._active_suppression_for_finding(conn, finding, scan.project_id)
            if active_suppression and finding.status not in {FindingStatus.fixed.value, FindingStatus.verified.value, FindingStatus.false_positive.value}:
                finding.status = FindingStatus.suppressed.value
                finding.suppression = active_suppression

            params: list[Any] = [finding.fingerprint, scan.id]
            query = """
                select scan_id, event as state from finding_history where fingerprint = %s and scan_id <> %s
                union all
                select scan_id, new_status as state from finding_lifecycle_events where fingerprint = %s and scan_id <> %s
            """
            params = [finding.fingerprint, scan.id, finding.fingerprint, scan.id]
            if scan.project_id:
                query = f"select * from ({query}) prior where prior.scan_id in (select id from scans where project_id = %s)"
                params.append(scan.project_id)
            rows = conn.execute(query, tuple(params)).fetchall()
            if rows:
                finding.recurrence_count = max(finding.recurrence_count, len({row["scan_id"] for row in rows}) + 1)
                if finding.baseline_state == BaselineState.new:
                    finding.baseline_state = BaselineState.existing
                if any(row["state"] in {"fixed", "verified"} for row in rows) and finding.status != FindingStatus.suppressed.value:
                    finding.status = FindingStatus.reintroduced.value
                    finding.baseline_state = BaselineState.reintroduced
            finding.last_seen = now

    def _active_suppression_for_finding(self, conn, finding, project_id: str | None):
        if not project_id:
            return None
        row = conn.execute(
            """
            select actor, reason, scope, expires_at, created_at
            from finding_lifecycle_events
            where project_id = %s
              and fingerprint = %s
              and new_status = 'suppressed'
              and (expires_at is null or expires_at > now())
            order by created_at desc
            limit 1
            """,
            (project_id, finding.fingerprint),
        ).fetchone()
        if not row:
            return None
        from nope_api.models import Suppression

        return Suppression(
            reason=row["reason"],
            user=row["actor"],
            actor=row["actor"],
            date=row["created_at"],
            expiry=row["expires_at"],
            scope=row["scope"] or "finding",
        )

    def _expire_suppressions_in_model(self, conn, scan: Scan, owner_user_id: str | None) -> bool:
        now = now_utc()
        changed = False
        for finding in scan.findings:
            if not finding.suppression or not finding.suppression.expiry or finding.suppression.expiry > now:
                continue
            previous = finding.status
            finding.suppression_expired_at = now
            finding.suppression = None
            finding.status = FindingStatus.reopened.value
            finding.lifecycle_version = max(1, finding.lifecycle_version) + 1
            finding.last_seen = now
            self._record_finding_lifecycle_event(
                conn,
                finding=finding,
                previous_status=previous,
                new_status=finding.status,
                actor="system",
                reason="Suppression expired automatically.",
                scope="finding",
                metadata={"automatic": True, "owner_user_id": owner_user_id},
            )
            changed = True
        return changed

    def _persist_scan_data_and_finding_rows(self, conn, scan: Scan) -> None:
        conn.execute("update scans set data = %s where id = %s", (Jsonb(scan.model_dump(mode="json")), scan.id))
        for finding in scan.findings:
            conn.execute(
                """
                update findings
                set status = %s,
                    last_seen = %s,
                    verified = %s,
                    status_version = %s,
                    suppressed_until = %s,
                    suppression_scope = %s,
                    suppression_reason = %s,
                    suppression_actor = %s,
                    data = %s
                where id = %s and scan_id = %s
                """,
                (
                    finding.status,
                    finding.last_seen,
                    finding.verified,
                    finding.lifecycle_version,
                    finding.suppression.expiry if finding.suppression else None,
                    finding.suppression.scope if finding.suppression else None,
                    finding.suppression.reason if finding.suppression else None,
                    (finding.suppression.actor or finding.suppression.user) if finding.suppression else None,
                    Jsonb(finding.model_dump(mode="json")),
                    finding.id,
                    scan.id,
                ),
            )

    def _record_finding_lifecycle_event(
        self,
        conn,
        *,
        finding,
        previous_status: str | None,
        new_status: str,
        actor: str,
        reason: str,
        scope: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            insert into finding_lifecycle_events (
              id, finding_id, scan_id, project_id, fingerprint, previous_status, new_status,
              actor, reason, scope, expires_at, status_version, metadata
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                new_id("fle"),
                finding.id,
                finding.scan_id,
                finding.project_id,
                finding.fingerprint,
                previous_status,
                new_status,
                actor,
                reason,
                scope,
                finding.suppression.expiry if finding.suppression else None,
                finding.lifecycle_version,
                Jsonb(metadata or {}),
            ),
        )
        conn.execute(
            """
            insert into finding_history (finding_id, fingerprint, scan_id, event, data)
            values (%s, %s, %s, %s, %s)
            """,
            (
                finding.id,
                finding.fingerprint,
                finding.scan_id,
                new_status,
                Jsonb(
                    {
                        "previous_status": previous_status,
                        "status": new_status,
                        "actor": actor,
                        "reason": reason,
                        "scope": scope,
                        "lifecycle_version": finding.lifecycle_version,
                    }
                ),
            ),
        )

    def get_scan(self, scan_id: str, owner_user_id: str | None = None) -> Scan | None:
        self.migrate()
        query = "select data from scans where id = %s"
        params: tuple[Any, ...] = (scan_id,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (scan_id, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
            if not row:
                return None
            scan = Scan(**row["data"])
            if self._expire_suppressions_in_model(conn, scan, owner_user_id):
                self._persist_scan_data_and_finding_rows(conn, scan)
        return scan

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

    def list_finding_lifecycle_events(
        self,
        scan_id: str,
        finding_id: str,
        owner_user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self.migrate()
        query = """
            select finding_lifecycle_events.*
            from finding_lifecycle_events
            join scans on scans.id = finding_lifecycle_events.scan_id
            where finding_lifecycle_events.scan_id = %s
              and finding_lifecycle_events.finding_id = %s
        """
        params: list[Any] = [scan_id, finding_id]
        if owner_user_id:
            query += " and scans.owner_user_id = %s"
            params.append(owner_user_id)
        query += " order by finding_lifecycle_events.created_at asc"
        with connect(self.settings) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def user_owns_scan(self, scan_id: str, owner_user_id: str) -> bool:
        self.migrate()
        with connect(self.settings) as conn:
            row = conn.execute(
                "select 1 from scans where id = %s and owner_user_id = %s",
                (scan_id, owner_user_id),
            ).fetchone()
        return row is not None

    def transition_finding(
        self,
        scan_id: str,
        finding_id: str,
        request: LifecycleTransitionRequest,
        owner_user_id: str | None,
    ) -> Scan | None:
        self.migrate()
        actor = request.actor or owner_user_id or "local-user"
        with connect(self.settings) as conn:
            params: tuple[Any, ...] = (scan_id,)
            owner_clause = ""
            if owner_user_id:
                owner_clause = " and owner_user_id = %s"
                params = (scan_id, owner_user_id)
            scan_row = conn.execute(f"select data from scans where id = %s{owner_clause} for update", params).fetchone()
            if not scan_row:
                return None
            finding_row = conn.execute(
                """
                select id, status_version
                from findings
                where scan_id = %s and id = %s
                for update
                """,
                (scan_id, finding_id),
            ).fetchone()
            if not finding_row:
                return None
            scan = Scan(**scan_row["data"])
            self._expire_suppressions_in_model(conn, scan, owner_user_id)
            finding = next((item for item in scan.findings if item.id == finding_id), None)
            if not finding:
                return None
            current_version = max(int(finding.lifecycle_version or 1), int(finding_row["status_version"] or 1))
            finding.lifecycle_version = current_version
            if request.expected_version is not None and request.expected_version != current_version:
                raise RuntimeError(f"Finding lifecycle version conflict: expected {request.expected_version}, current {current_version}.")
            previous = finding.status
            finding.scan_id = scan.id
            finding.project_id = scan.project_id
            apply_transition(finding, request, actor=actor)
            self._persist_scan_data_and_finding_rows(conn, scan)
            self._record_finding_lifecycle_event(
                conn,
                finding=finding,
                previous_status=previous,
                new_status=finding.status,
                actor=actor,
                reason=request.reason,
                scope=request.scope,
                metadata=request.metadata,
            )
            conn.execute(
                """
                insert into audit_logs (owner_user_id, project_id, scan_id, action, actor, data)
                values (%s, %s, %s, %s, %s, %s)
                """,
                (
                    owner_user_id,
                    scan.project_id,
                    scan.id,
                    "finding.lifecycle.updated",
                    actor,
                    Jsonb(
                        {
                            "finding_id": finding.id,
                            "fingerprint": finding.fingerprint,
                            "previous_status": previous,
                            "new_status": finding.status,
                            "reason": request.reason,
                            "scope": request.scope,
                            "lifecycle_version": finding.lifecycle_version,
                        }
                    ),
                ),
            )
            return scan

    def record_scan_event(
        self,
        scan_id: str,
        event_type: str,
        *,
        owner_user_id: str | None = None,
        stage_id: str | None = None,
        scanner_run_id: str | None = None,
        previous_state: str | None = None,
        new_state: str | None = None,
        progress: int | None = None,
        message: str = "",
        metadata: dict[str, Any] | None = None,
        error_code: str | None = None,
        error_details: str | None = None,
        attempt: int = 1,
        worker_identity: str | None = None,
        idempotency_key: str | None = None,
    ) -> ScanEvent | None:
        self.migrate()
        event_key = idempotency_key or f"{event_type}:{stage_id or ''}:{scanner_run_id or ''}:{new_state or ''}:{attempt}"
        with connect(self.settings) as conn:
            params: tuple[Any, ...] = (scan_id,)
            owner_clause = ""
            if owner_user_id:
                owner_clause = " and owner_user_id = %s"
                params = (scan_id, owner_user_id)
            scan_row = conn.execute(f"select id from scans where id = %s{owner_clause}", params).fetchone()
            if not scan_row:
                return None
            existing = conn.execute(
                """
                select id, scan_id, stage_id, scanner_run_id, event_type, previous_state, new_state,
                       progress, message, metadata, error_code, error_details, attempt, worker_identity,
                       created_at, sequence, idempotency_key
                from scan_events
                where scan_id = %s and idempotency_key = %s
                """,
                (scan_id, event_key),
            ).fetchone()
            if existing:
                data = dict(existing)
                data["metadata"] = dict(data["metadata"] or {})
                return ScanEvent(**data)

            conn.execute("select pg_advisory_xact_lock(hashtext(%s))", (scan_id,))
            latest = conn.execute(
                "select sequence, progress from scan_events where scan_id = %s order by sequence desc limit 1",
                (scan_id,),
            ).fetchone()
            sequence = int(latest["sequence"]) + 1 if latest else 1
            if progress is not None:
                progress = max(0, min(100, int(progress)))
                if latest and event_type not in {"retry_scheduled", "retry_started"}:
                    previous_progress = latest["progress"]
                    if previous_progress is not None:
                        progress = max(progress, int(previous_progress))
            row = conn.execute(
                """
                insert into scan_events (
                  id, scan_id, stage_id, scanner_run_id, event_type, previous_state, new_state,
                  progress, message, metadata, error_code, error_details, attempt, worker_identity,
                  sequence, idempotency_key
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id, scan_id, stage_id, scanner_run_id, event_type, previous_state, new_state,
                          progress, message, metadata, error_code, error_details, attempt, worker_identity,
                          created_at, sequence, idempotency_key
                """,
                (
                    new_id("evt"),
                    scan_id,
                    stage_id,
                    scanner_run_id,
                    event_type,
                    previous_state,
                    new_state,
                    progress,
                    _redact_event_text(message),
                    Jsonb(metadata or {}),
                    error_code,
                    _redact_event_text(error_details),
                    max(1, int(attempt or 1)),
                    worker_identity,
                    sequence,
                    event_key,
                ),
            ).fetchone()
        data = dict(row)
        data["metadata"] = dict(data["metadata"] or {})
        return ScanEvent(**data)

    def list_scan_events(
        self,
        scan_id: str,
        owner_user_id: str | None = None,
        *,
        after_sequence: int | None = None,
        limit: int = 100,
    ) -> dict[str, Any] | None:
        self.migrate()
        limit = max(1, min(500, int(limit or 100)))
        query = """
            select scan_events.id, scan_events.scan_id, scan_events.stage_id, scan_events.scanner_run_id,
                   scan_events.event_type, scan_events.previous_state, scan_events.new_state,
                   scan_events.progress, scan_events.message, scan_events.metadata,
                   scan_events.error_code, scan_events.error_details, scan_events.attempt,
                   scan_events.worker_identity, scan_events.created_at, scan_events.sequence,
                   scan_events.idempotency_key
            from scan_events
            join scans on scans.id = scan_events.scan_id
            where scan_events.scan_id = %s
        """
        params: list[Any] = [scan_id]
        if owner_user_id:
            query += " and scans.owner_user_id = %s"
            params.append(owner_user_id)
        if after_sequence is not None:
            query += " and scan_events.sequence > %s"
            params.append(int(after_sequence))
        query += " order by scan_events.sequence asc limit %s"
        params.append(limit + 1)
        with connect(self.settings) as conn:
            scan_exists_query = "select data from scans where id = %s"
            scan_params: tuple[Any, ...] = (scan_id,)
            if owner_user_id:
                scan_exists_query += " and owner_user_id = %s"
                scan_params = (scan_id, owner_user_id)
            scan_row = conn.execute(scan_exists_query, scan_params).fetchone()
            if not scan_row:
                return None
            rows = conn.execute(query, tuple(params)).fetchall()
        items = []
        for row in rows[:limit]:
            data = dict(row)
            data["metadata"] = dict(data["metadata"] or {})
            items.append(ScanEvent(**data).model_dump(mode="json"))
        return {
            "events": items,
            "has_more": len(rows) > limit,
            "next_after_sequence": items[-1]["sequence"] if items else after_sequence,
            "total": self.count_scan_events(scan_id, owner_user_id),
        }

    def count_scan_events(self, scan_id: str, owner_user_id: str | None = None) -> int:
        self.migrate()
        query = "select count(*) as count from scan_events join scans on scans.id = scan_events.scan_id where scan_events.scan_id = %s"
        params: tuple[Any, ...] = (scan_id,)
        if owner_user_id:
            query += " and scans.owner_user_id = %s"
            params = (scan_id, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return int(row["count"] if row else 0)

    def backfill_scan_events_from_snapshot(self, scan: Scan, owner_user_id: str | None = None) -> int:
        if self.count_scan_events(scan.id, owner_user_id) > 0:
            return 0
        progress = 0
        inserted = 0
        created = self.record_scan_event(
            scan.id,
            "scan_created",
            owner_user_id=owner_user_id,
            new_state="queued",
            progress=progress,
            message="Backfilled from persisted scan snapshot.",
            idempotency_key="backfill:scan_created",
        )
        inserted += 1 if created else 0
        stage_total = max(len(scan.stages), 1)
        for index, stage in enumerate(scan.stages):
            status = str(stage.get("status") or "completed")
            event_type = _stage_event_type(status)
            progress = min(99, max(progress, round(((index + 1) / stage_total) * 80)))
            event = self.record_scan_event(
                scan.id,
                event_type,
                owner_user_id=owner_user_id,
                stage_id=f"stage:{index}",
                new_state=status,
                progress=progress,
                message=str(stage.get("message") or stage.get("name") or ""),
                metadata={"stage": stage, "backfilled": True},
                idempotency_key=f"backfill:stage:{index}:{status}",
            )
            inserted += 1 if event else 0
        for index, run in enumerate(scan.scanner_runs):
            started = self.record_scan_event(
                scan.id,
                "scanner_started",
                owner_user_id=owner_user_id,
                scanner_run_id=f"scanner:{index}:{run.scanner}",
                new_state="running",
                progress=progress,
                message=f"{run.scanner} started.",
                metadata={"scanner": run.scanner, "backfilled": True},
                idempotency_key=f"backfill:scanner:{index}:started",
            )
            inserted += 1 if started else 0
            terminal_type = _scanner_event_type(run.status, run.message)
            event = self.record_scan_event(
                scan.id,
                terminal_type,
                owner_user_id=owner_user_id,
                scanner_run_id=f"scanner:{index}:{run.scanner}",
                new_state=run.status,
                progress=progress,
                message=run.message or f"{run.scanner} {run.status}.",
                metadata={"scanner": run.model_dump(mode="json"), "backfilled": True},
                error_code=run.status if run.status != "passed" else None,
                error_details=run.message if run.status != "passed" else None,
                idempotency_key=f"backfill:scanner:{index}:{run.status}",
            )
            inserted += 1 if event else 0
        if scan.ai_review.status not in {"Not tested"}:
            event_type = "qwen_completed" if scan.ai_review.status in {"Complete", "Partial"} else "qwen_failed"
            event = self.record_scan_event(
                scan.id,
                event_type,
                owner_user_id=owner_user_id,
                new_state=scan.ai_review.status,
                progress=95,
                message=scan.ai_review.message,
                metadata={"ai_review": scan.ai_review.model_dump(mode="json"), "backfilled": True},
                error_code="qwen_failed" if event_type == "qwen_failed" else None,
                error_details=scan.ai_review.message if event_type == "qwen_failed" else None,
                idempotency_key=f"backfill:qwen:{scan.ai_review.status}",
            )
            inserted += 1 if event else 0
        terminal_type = {"completed": "scan_completed", "partial": "scan_partial", "failed": "scan_failed", "cancelled": "scan_cancelled"}.get(scan.status, "scan_started")
        event = self.record_scan_event(
            scan.id,
            terminal_type,
            owner_user_id=owner_user_id,
            new_state=scan.status,
            progress=100 if scan.status in {"completed", "partial", "failed", "cancelled"} else progress,
            message=scan.verdict,
            idempotency_key=f"backfill:terminal:{scan.status}",
        )
        inserted += 1 if event else 0
        return inserted

    def delete_scan(self, scan_id: str, owner_user_id: str | None = None) -> bool:
        self.migrate()
        query = "delete from scans where id = %s"
        params: tuple[Any, ...] = (scan_id,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (scan_id, owner_user_id)
        with connect(self.settings) as conn:
            self._ensure_deleted_scans_table(conn)
            conn.execute(
                """
                insert into deleted_scans (scan_id, owner_user_id)
                values (%s, %s)
                on conflict (scan_id) do update set deleted_at = now(), owner_user_id = excluded.owner_user_id
                """,
                (scan_id, owner_user_id),
            )
            conn.execute("delete from uploaded_artifacts where scan_id = %s", (scan_id,))
            conn.execute("delete from repository_snapshots where id = %s", (f"snap_{scan_id}",))
            row = conn.execute(query + " returning id", params).fetchone()
        return row is not None

    def get_ai_action_cache(self, cache_key: str, owner_user_id: str | None = None) -> dict[str, Any] | None:
        self.migrate()
        query = "select * from ai_action_cache where cache_key = %s and expires_at > now()"
        params: tuple[Any, ...] = (cache_key,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (cache_key, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
            if row:
                conn.execute("update ai_action_cache set last_used_at = now() where cache_key = %s", (cache_key,))
        return dict(row) if row else None

    def save_ai_action_cache(
        self,
        *,
        cache_key: str,
        owner_user_id: str | None,
        finding_fingerprint: str,
        action: str,
        provider: str,
        model: str,
        quantization: str | None,
        prompt_version: str,
        rag_version: str,
        evidence_hash: str,
        settings_hash: str,
        result: dict[str, Any],
        context_metadata: dict[str, Any],
        ttl_seconds: int,
    ) -> None:
        self.migrate()
        with connect(self.settings) as conn:
            conn.execute(
                """
                insert into ai_action_cache (
                  cache_key, owner_user_id, finding_fingerprint, action, provider, model, quantization,
                  prompt_version, rag_version, evidence_hash, settings_hash, result, context_metadata,
                  expires_at, last_used_at
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now() + (%s * interval '1 second'), now())
                on conflict (cache_key) do update set
                  result = excluded.result,
                  context_metadata = excluded.context_metadata,
                  expires_at = excluded.expires_at,
                  last_used_at = now()
                """,
                (
                    cache_key,
                    owner_user_id,
                    finding_fingerprint,
                    action,
                    provider,
                    model,
                    quantization,
                    prompt_version,
                    rag_version,
                    evidence_hash,
                    settings_hash,
                    Jsonb(result),
                    Jsonb(context_metadata),
                    int(ttl_seconds),
                ),
            )

    def create_ai_action_job(
        self,
        *,
        job_id: str,
        owner_user_id: str | None,
        scan_id: str | None,
        finding_id: str,
        finding_fingerprint: str,
        action: str,
        status: str,
        provider: str,
        model: str,
        quantization: str | None,
        prompt_version: str,
        rag_version: str,
        evidence_hash: str,
        settings_hash: str,
        cache_key: str,
        message: str,
        context_chunks: int = 0,
        result: dict[str, Any] | None = None,
        cached: bool = False,
        latency_ms: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        completed_at = "now()" if status in {"completed", "failed", "cancelled"} else "null"
        with connect(self.settings) as conn:
            row = conn.execute(
                f"""
                insert into ai_action_jobs (
                  id, owner_user_id, scan_id, finding_id, finding_fingerprint, action, status, provider,
                  model, quantization, prompt_version, rag_version, evidence_hash, settings_hash,
                  cache_key, completed_at, latency_ms, cached, message, context_chunks, result, metadata
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, {completed_at}, %s, %s, %s, %s, %s, %s)
                returning *
                """,
                (
                    job_id,
                    owner_user_id,
                    scan_id,
                    finding_id,
                    finding_fingerprint,
                    action,
                    status,
                    provider,
                    model,
                    quantization,
                    prompt_version,
                    rag_version,
                    evidence_hash,
                    settings_hash,
                    cache_key,
                    latency_ms,
                    cached,
                    _redact_event_text(message),
                    context_chunks,
                    Jsonb(result) if result is not None else None,
                    Jsonb(metadata or {}),
                ),
            ).fetchone()
        return dict(row)

    def get_ai_action_job(self, job_id: str, owner_user_id: str | None = None) -> dict[str, Any] | None:
        self.migrate()
        query = "select * from ai_action_jobs where id = %s"
        params: tuple[Any, ...] = (job_id,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (job_id, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def start_ai_action_job(self, job_id: str, owner_user_id: str | None = None) -> dict[str, Any] | None:
        self.migrate()
        query = "update ai_action_jobs set status = 'running', started_at = now(), message = %s where id = %s and status = 'queued'"
        params: tuple[Any, ...] = ("Qwen action is running.", job_id)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = ("Qwen action is running.", job_id, owner_user_id)
        query += " returning *"
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def complete_ai_action_job(
        self,
        job_id: str,
        *,
        owner_user_id: str | None,
        status: str,
        message: str,
        result: dict[str, Any] | None,
        latency_ms: int | None,
        context_chunks: int,
        cached: bool = False,
        error_code: str | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        self.migrate()
        query = """
            update ai_action_jobs
            set status = %s,
                completed_at = case when %s in ('completed', 'failed') then now() else completed_at end,
                cancelled_at = case when %s = 'cancelled' then now() else cancelled_at end,
                latency_ms = %s,
                cached = %s,
                message = %s,
                context_chunks = %s,
                result = %s,
                error_code = %s,
                error_message = %s,
                metadata = coalesce(metadata, '{}'::jsonb) || %s
            where id = %s and status <> 'cancelled'
        """
        params: tuple[Any, ...] = (
            status,
            status,
            status,
            latency_ms,
            cached,
            _redact_event_text(message),
            context_chunks,
            Jsonb(result) if result is not None else None,
            error_code,
            _redact_event_text(error_message),
            Jsonb(metadata or {}),
            job_id,
        )
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = params + (owner_user_id,)
        query += " returning *"
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def cancel_ai_action_job(self, job_id: str, owner_user_id: str | None = None) -> dict[str, Any] | None:
        self.migrate()
        query = """
            update ai_action_jobs
            set status = 'cancelled', cancelled_at = now(), message = %s
            where id = %s and status in ('queued', 'running')
        """
        params: tuple[Any, ...] = ("Qwen action was cancelled.", job_id)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = ("Qwen action was cancelled.", job_id, owner_user_id)
        query += " returning *"
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def delete_project(self, project_id: str, owner_user_id: str | None = None) -> bool:
        self.migrate()
        query = "delete from projects where id = %s"
        params: tuple[Any, ...] = (project_id,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (project_id, owner_user_id)
        with connect(self.settings) as conn:
            self._ensure_deleted_scans_table(conn)
            scan_ids = [
                row["id"]
                for row in conn.execute(
                    "select id from scans where project_id = %s" + (" and owner_user_id = %s" if owner_user_id else ""),
                    (project_id, owner_user_id) if owner_user_id else (project_id,),
                ).fetchall()
            ]
            for scan_id in scan_ids:
                conn.execute(
                    """
                    insert into deleted_scans (scan_id, owner_user_id)
                    values (%s, %s)
                    on conflict (scan_id) do update set deleted_at = now(), owner_user_id = excluded.owner_user_id
                    """,
                    (scan_id, owner_user_id),
                )
            conn.execute("delete from uploaded_artifacts where project_id = %s", (project_id,))
            if scan_ids:
                conn.execute("delete from uploaded_artifacts where scan_id = any(%s)", (scan_ids,))
            conn.execute("delete from repository_snapshots where project_id = %s", (project_id,))
            conn.execute("delete from scans where project_id = %s" + (" and owner_user_id = %s" if owner_user_id else ""), (project_id, owner_user_id) if owner_user_id else (project_id,))
            conn.execute(
                "delete from application_settings where owner_user_id is not distinct from %s and key = %s",
                (owner_user_id, f"project:{project_id}"),
            )
            row = conn.execute(query + " returning id", params).fetchone()
        return row is not None

    def user_owns_project(self, project_id: str, owner_user_id: str | None) -> bool:
        self.migrate()
        query = "select 1 from projects where id = %s"
        params: tuple[Any, ...] = (project_id,)
        if owner_user_id:
            query += " and owner_user_id = %s"
            params = (project_id, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return row is not None

    def save_application_setting(self, owner_user_id: str | None, key: str, value: dict[str, Any]) -> dict[str, Any]:
        self.migrate()
        setting_id = new_id("set")
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                insert into application_settings (id, owner_user_id, key, value)
                values (%s, %s, %s, %s)
                on conflict (owner_user_id, key) do update set
                  value = excluded.value,
                  updated_at = now()
                returning id, owner_user_id, key, value, created_at, updated_at
                """,
                (setting_id, owner_user_id, key, Jsonb(value)),
            ).fetchone()
        return dict(row)

    def get_application_setting(self, owner_user_id: str | None, key: str) -> dict[str, Any] | None:
        self.migrate()
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                select id, owner_user_id, key, value, created_at, updated_at
                from application_settings
                where owner_user_id is not distinct from %s and key = %s
                """,
                (owner_user_id, key),
            ).fetchone()
        return dict(row) if row else None

    def save_github_contract(self, owner_user_id: str, data: dict[str, Any], status: str) -> dict[str, Any]:
        self.migrate()
        with connect(self.settings) as conn:
            existing = conn.execute(
                """
                select id from github_connections
                where owner_user_id = %s and provider = 'github'
                order by created_at desc
                limit 1
                """,
                (owner_user_id,),
            ).fetchone()
            if existing:
                row = conn.execute(
                    """
                    update github_connections
                    set status = %s, data = %s, updated_at = now()
                    where id = %s and owner_user_id = %s
                    returning id, owner_user_id, provider, status, created_at, updated_at, data
                    """,
                    (status, Jsonb(data), existing["id"], owner_user_id),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    insert into github_connections (id, owner_user_id, provider, status, data)
                    values (%s, %s, 'github', %s, %s)
                    returning id, owner_user_id, provider, status, created_at, updated_at, data
                    """,
                    (new_id("ghc"), owner_user_id, status, Jsonb(data)),
                ).fetchone()
        return dict(row)

    def get_github_contract(self, owner_user_id: str) -> dict[str, Any] | None:
        self.migrate()
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                select id, owner_user_id, provider, status, created_at, updated_at, data
                from github_connections
                where owner_user_id = %s and provider = 'github'
                order by created_at desc
                limit 1
                """,
                (owner_user_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_github_repository_references(self, owner_user_id: str) -> list[dict[str, Any]]:
        self.migrate()
        with connect(self.settings) as conn:
            rows = conn.execute(
                """
                select github_repository_references.id, github_repository_references.full_name,
                       github_repository_references.default_branch, github_repository_references.private,
                       github_repository_references.created_at, github_repository_references.data
                from github_repository_references
                join github_installations on github_installations.id = github_repository_references.installation_id
                join github_connections on github_connections.id = github_installations.connection_id
                where github_connections.owner_user_id = %s
                order by github_repository_references.created_at desc
                """,
                (owner_user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_model_configuration(
        self,
        owner_user_id: str | None,
        provider: str,
        model_name: str,
        runtime_endpoint: str,
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        config = {
            "id": new_id("model"),
            "owner_user_id": owner_user_id,
            "provider": provider,
            "model_name": model_name,
            "runtime_endpoint": runtime_endpoint,
            "settings": settings or {},
        }
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                insert into model_configurations (id, owner_user_id, provider, model_name, runtime_endpoint, settings)
                values (%s, %s, %s, %s, %s, %s)
                returning id, owner_user_id, provider, model_name, runtime_endpoint, settings, created_at, updated_at
                """,
                (
                    config["id"],
                    owner_user_id,
                    provider,
                    model_name,
                    runtime_endpoint,
                    Jsonb(config["settings"]),
                ),
            ).fetchone()
        return dict(row)

    def save_scanner_configuration(
        self,
        owner_user_id: str | None,
        scanner: str,
        enabled: bool,
        timeout_seconds: int | None = None,
        settings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        config = {
            "id": new_id("scanner_cfg"),
            "owner_user_id": owner_user_id,
            "scanner": scanner,
            "enabled": enabled,
            "timeout_seconds": timeout_seconds,
            "settings": settings or {},
        }
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                insert into scanner_configurations (
                  id, owner_user_id, scanner, enabled, timeout_seconds, settings
                )
                values (%s, %s, %s, %s, %s, %s)
                returning id, owner_user_id, scanner, enabled, timeout_seconds, settings, created_at, updated_at
                """,
                (
                    config["id"],
                    owner_user_id,
                    scanner,
                    enabled,
                    timeout_seconds,
                    Jsonb(config["settings"]),
                ),
            ).fetchone()
        return dict(row)

    def create_security_baseline(
        self,
        project_id: str | None,
        scan_id: str | None,
        name: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        baseline = {"id": new_id("base"), "project_id": project_id, "scan_id": scan_id, "name": name, "data": data or {}}
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                insert into security_baselines (id, project_id, scan_id, name, data)
                values (%s, %s, %s, %s, %s)
                returning id, project_id, scan_id, name, created_at, data
                """,
                (baseline["id"], project_id, scan_id, name, Jsonb(baseline["data"])),
            ).fetchone()
        return dict(row)

    def get_security_baseline(self, baseline_id: str, owner_user_id: str | None = None) -> dict[str, Any] | None:
        self.migrate()
        query = """
            select security_baselines.id, security_baselines.project_id, security_baselines.scan_id,
                   security_baselines.name, security_baselines.created_at, security_baselines.data
            from security_baselines
            left join scans on scans.id = security_baselines.scan_id
            left join projects on projects.id = security_baselines.project_id
            where security_baselines.id = %s
        """
        params: tuple[Any, ...] = (baseline_id,)
        if owner_user_id:
            query += " and (scans.owner_user_id = %s or projects.owner_user_id = %s)"
            params = (baseline_id, owner_user_id, owner_user_id)
        with connect(self.settings) as conn:
            row = conn.execute(query, params).fetchone()
        return dict(row) if row else None

    def list_security_baselines(self, owner_user_id: str | None = None, project_id: str | None = None) -> list[dict[str, Any]]:
        self.migrate()
        query = """
            select security_baselines.id, security_baselines.project_id, security_baselines.scan_id,
                   security_baselines.name, security_baselines.created_at, security_baselines.data
            from security_baselines
            left join scans on scans.id = security_baselines.scan_id
            left join projects on projects.id = security_baselines.project_id
            where 1 = 1
        """
        params: list[Any] = []
        if owner_user_id:
            query += " and (scans.owner_user_id = %s or projects.owner_user_id = %s)"
            params.extend([owner_user_id, owner_user_id])
        if project_id:
            query += " and security_baselines.project_id = %s"
            params.append(project_id)
        query += " order by security_baselines.created_at desc"
        with connect(self.settings) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def create_drift_event(
        self,
        baseline_id: str | None,
        scan_id: str,
        event_type: str,
        message: str,
        severity: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        drift = {"id": new_id("drift"), "data": data or {}}
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                insert into drift_events (id, baseline_id, scan_id, event_type, severity, message, data)
                values (%s, %s, %s, %s, %s, %s, %s)
                returning id, baseline_id, scan_id, event_type, severity, message, created_at, data
                """,
                (drift["id"], baseline_id, scan_id, event_type, severity, message, Jsonb(drift["data"])),
            ).fetchone()
        return dict(row)

    def list_drift_events(self, scan_id: str, owner_user_id: str | None = None) -> list[dict[str, Any]]:
        self.migrate()
        query = """
            select drift_events.id, drift_events.baseline_id, drift_events.scan_id, drift_events.event_type,
                   drift_events.severity, drift_events.message, drift_events.created_at, drift_events.data
            from drift_events
            join scans on scans.id = drift_events.scan_id
            where drift_events.scan_id = %s
        """
        params: tuple[Any, ...] = (scan_id,)
        if owner_user_id:
            query += " and scans.owner_user_id = %s"
            params = (scan_id, owner_user_id)
        query += " order by drift_events.created_at desc"
        with connect(self.settings) as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def record_audit_log(
        self,
        action: str,
        owner_user_id: str | None = None,
        project_id: str | None = None,
        scan_id: str | None = None,
        actor: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.migrate()
        with connect(self.settings) as conn:
            row = conn.execute(
                """
                insert into audit_logs (owner_user_id, project_id, scan_id, action, actor, data)
                values (%s, %s, %s, %s, %s, %s)
                returning id, owner_user_id, project_id, scan_id, action, actor, created_at, data
                """,
                (owner_user_id, project_id, scan_id, action, actor, Jsonb(data or {})),
            ).fetchone()
        return dict(row)

    def get_report(
        self,
        scan_id: str,
        fmt: str,
        owner_user_id: str | None = None,
    ) -> tuple[str, str | bytes] | None:
        payload = self.get_report_payload(scan_id, fmt, owner_user_id)
        if not payload:
            return None
        return str(payload["media_type"]), payload["body"]

    def get_report_payload(
        self,
        scan_id: str,
        fmt: str,
        owner_user_id: str | None = None,
    ) -> dict[str, Any] | None:
        self.migrate()
        query = """
            select reports.id, reports.scan_id, reports.format, reports.media_type, reports.body,
                   reports.body_sha256, reports.byte_size, reports.generated_at, reports.data
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
        data = dict(row["data"] or {})
        body: str | bytes = str(row["body"])
        if data.get("encoding") == "base64":
            body = base64.b64decode(body.encode("ascii"))
        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "format": row["format"],
            "media_type": row["media_type"],
            "body": body,
            "body_sha256": row["body_sha256"],
            "byte_size": row["byte_size"],
            "generated_at": row["generated_at"],
            "data": data,
        }

    def get_report_status(self, scan_id: str, fmt: str, owner_user_id: str | None = None) -> dict[str, Any] | None:
        payload = self.get_report_payload(scan_id, fmt, owner_user_id)
        if not payload:
            return None
        data = payload["data"]
        return {
            "id": payload["id"],
            "scan_id": payload["scan_id"],
            "format": payload["format"],
            "media_type": payload["media_type"],
            "status": data.get("status", "completed"),
            "storage_url": data.get("storage_url"),
            "artifact_id": data.get("artifact_id"),
            "body_sha256": payload["body_sha256"],
            "byte_size": payload["byte_size"],
            "generated_at": payload["generated_at"],
        }

    def save_report(
        self,
        scan: Scan,
        fmt: str,
        media_type: str,
        body: str | bytes,
        *,
        owner_user_id: str | None = None,
        status: str = "completed",
    ) -> dict[str, Any]:
        self.migrate()
        encoded = body if isinstance(body, bytes) else body.encode("utf-8")
        body_sha256 = sha256(encoded).hexdigest()
        text_body = base64.b64encode(encoded).decode("ascii") if isinstance(body, bytes) else body
        metadata: dict[str, Any] = {
            "scan_id": scan.id,
            "format": fmt,
            "status": status,
            "body_sha256": body_sha256,
            "byte_size": len(encoded),
        }
        if isinstance(body, bytes):
            artifact = put_binary_artifact(
                self.settings,
                scan_id=scan.id,
                artifact_type="report_pdf",
                name=f"{scan.id}-report",
                body=body,
                content_type=media_type,
                extension=fmt,
            )
            metadata["encoding"] = "base64"
            if artifact:
                metadata.update(
                    {
                        "artifact_id": artifact["id"],
                        "storage_url": artifact["storage_url"],
                        "object_name": artifact["object_name"],
                    }
                )
        with connect(self.settings) as conn:
            row = conn.execute(
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
                returning id, scan_id, format, media_type, body_sha256, byte_size, generated_at, data
                """,
                (
                    f"rpt_{scan.id}_{fmt}",
                    scan.id,
                    fmt,
                    media_type or REPORT_MEDIA_TYPES.get(fmt, "application/octet-stream"),
                    text_body,
                    body_sha256,
                    len(encoded),
                    Jsonb(metadata),
                ),
            ).fetchone()
            if isinstance(body, bytes) and metadata.get("artifact_id"):
                conn.execute(
                    """
                    insert into uploaded_artifacts (
                      id, scan_id, artifact_type, filename, storage_url, size_bytes, sha256, data
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (id) do nothing
                    """,
                    (
                        metadata["artifact_id"],
                        scan.id,
                        "report_pdf",
                        f"{scan.id}-report.{fmt}",
                        metadata["storage_url"],
                        len(encoded),
                        body_sha256,
                        Jsonb(metadata),
                    ),
                )
                conn.execute(
                    """
                    insert into job_artifacts (id, scan_id, artifact_type, storage_url, data)
                    values (%s, %s, %s, %s, %s)
                    on conflict (id) do nothing
                    """,
                    (
                        f"job_{metadata['artifact_id']}",
                        scan.id,
                        "report_pdf",
                        metadata["storage_url"],
                        Jsonb(metadata),
                    ),
                )
        result = dict(row)
        result["data"] = dict(result["data"] or {})
        return result

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
                encoded = body if isinstance(body, bytes) else body.encode("utf-8")
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
                        base64.b64encode(encoded).decode("ascii") if isinstance(body, bytes) else body,
                        body_sha256,
                        len(encoded),
                        Jsonb({"body_sha256": body_sha256, "byte_size": len(encoded), "encoding": "base64"} if isinstance(body, bytes) else {"body_sha256": body_sha256, "byte_size": len(encoded)}),
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
                  first_seen, last_seen, fix_available, verified, data, status_version,
                  suppressed_until, suppression_scope, suppression_reason, suppression_actor
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    finding.lifecycle_version,
                    finding.suppression.expiry if finding.suppression else None,
                    finding.suppression.scope if finding.suppression else None,
                    finding.suppression.reason if finding.suppression else None,
                    (finding.suppression.actor or finding.suppression.user) if finding.suppression else None,
                ),
            )
            conn.execute(
                """
                insert into finding_history (finding_id, fingerprint, scan_id, event, data)
                values (%s, %s, %s, %s, %s)
                """,
                (
                    finding.id,
                    finding.fingerprint,
                    scan.id,
                    finding.status if finding.status != FindingStatus.new.value else "observed",
                    Jsonb(
                        {
                            "status": finding.status,
                            "schema_version": finding.schema_version,
                            "original_fingerprint": finding.original_fingerprint,
                            "correlation_id": finding.correlation_id,
                            "scanner_sources": finding.scanner_sources,
                            "recurrence_count": finding.recurrence_count,
                            "baseline_state": finding.baseline_state.value,
                            "lifecycle_version": finding.lifecycle_version,
                            "suppression": finding.suppression.model_dump(mode="json") if finding.suppression else None,
                            "suppression_expired_at": finding.suppression_expired_at.isoformat() if finding.suppression_expired_at else None,
                        }
                    ),
                ),
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
            encoded = body if isinstance(body, bytes) else body.encode("utf-8")
            body_sha256 = sha256(encoded).hexdigest()
            text_body = base64.b64encode(encoded).decode("ascii") if isinstance(body, bytes) else body
            metadata = {
                "scan_id": scan.id,
                "format": fmt,
                "status": "completed",
                "body_sha256": body_sha256,
                "byte_size": len(encoded),
            }
            if isinstance(body, bytes):
                metadata["encoding"] = "base64"
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
                    text_body,
                    body_sha256,
                    len(encoded),
                    Jsonb(metadata),
                ),
            )

    def _upsert_repository_snapshot(self, conn, scan: Scan) -> None:
        if not scan.project_id or not (scan.repository_name or scan.branch or scan.commit_sha):
            return
        snapshot_id = f"snap_{scan.id}"
        conn.execute(
            """
            insert into repository_snapshots (
              id, project_id, branch, commit_sha, upload_name, created_at
            )
            values (%s, %s, %s, %s, %s, %s)
            on conflict (id) do update set
              project_id = excluded.project_id,
              branch = excluded.branch,
              commit_sha = excluded.commit_sha,
              upload_name = excluded.upload_name
            """,
            (
                snapshot_id,
                scan.project_id,
                scan.branch,
                scan.commit_sha,
                scan.repository_name,
                scan.started_at,
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
