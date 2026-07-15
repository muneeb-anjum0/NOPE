import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from nope_api.config import Settings
from nope_api.db import connect, run_migrations


def _connect(settings: Settings):
    return connect(settings)


class AuthRateLimitError(PermissionError):
    ...


_LOGIN_FAILURES: dict[str, list[float]] = {}
_LOGIN_FAILURE_WINDOW_SECONDS = 300
_LOGIN_FAILURE_LIMIT = 5


def clear_login_rate_limits() -> None:
    _LOGIN_FAILURES.clear()


def _rate_limit_key(email: str) -> str:
    return email.strip().lower()


def _check_login_rate_limit(email: str) -> None:
    key = _rate_limit_key(email)
    now = time.monotonic()
    attempts = [item for item in _LOGIN_FAILURES.get(key, []) if now - item < _LOGIN_FAILURE_WINDOW_SECONDS]
    _LOGIN_FAILURES[key] = attempts
    if len(attempts) >= _LOGIN_FAILURE_LIMIT:
        raise AuthRateLimitError("Too many failed login attempts. Try again later.")


def _record_login_failure(email: str) -> None:
    key = _rate_limit_key(email)
    now = time.monotonic()
    attempts = [item for item in _LOGIN_FAILURES.get(key, []) if now - item < _LOGIN_FAILURE_WINDOW_SECONDS]
    attempts.append(now)
    _LOGIN_FAILURES[key] = attempts


def _clear_login_failure(email: str) -> None:
    _LOGIN_FAILURES.pop(_rate_limit_key(email), None)


def init_auth_db(settings: Settings) -> None:
    run_migrations(settings)


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, digest_hex = stored.split("$", 2)
    except ValueError:
        return False
    candidate = _hash_password(password, bytes.fromhex(salt_hex)).split("$", 2)[2]
    return secrets.compare_digest(candidate, digest_hex)


def create_or_login(settings: Settings, email: str, password: str) -> dict:
    normalized = email.strip().lower()
    if not normalized or len(password) < 8:
        raise ValueError("Email is required and password must be at least 8 characters.")
    _check_login_rate_limit(normalized)
    init_auth_db(settings)
    with _connect(settings) as conn:
        user = conn.execute("select * from local_users where email = %s", (normalized,)).fetchone()
        if user is None:
            user_id = f"user_{secrets.token_hex(8)}"
            conn.execute(
                "insert into local_users (id, email, password_hash) values (%s, %s, %s)",
                (user_id, normalized, _hash_password(password)),
            )
            user = {"id": user_id, "email": normalized}
        elif not _verify_password(password, user["password_hash"]):
            _record_login_failure(normalized)
            raise PermissionError("Invalid local credentials.")
        _clear_login_failure(normalized)
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        conn.execute(
            "insert into local_sessions (token, user_id, expires_at) values (%s, %s, %s)",
            (token, user["id"], expires_at),
        )
        return {"token": token, "user": {"id": user["id"], "email": user["email"]}, "expires_at": expires_at.isoformat()}


def get_user_for_token(settings: Settings, token: str | None) -> dict | None:
    if not token:
        return None
    init_auth_db(settings)
    with _connect(settings) as conn:
        row = conn.execute(
            """
            select u.id, u.email, u.created_at
            from local_sessions s
            join local_users u on u.id = s.user_id
            where s.token = %s and s.expires_at > now()
            """,
            (token,),
        ).fetchone()
    return dict(row) if row else None


def delete_session(settings: Settings, token: str | None) -> None:
    if not token:
        return
    init_auth_db(settings)
    with _connect(settings) as conn:
        conn.execute("delete from local_sessions where token = %s", (token,))
