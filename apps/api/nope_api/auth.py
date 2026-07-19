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
_PASSWORD_PBKDF2_ITERATIONS = 600_000


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


def _redis_client(settings: Settings):
    try:
        from redis import Redis
    except ImportError:
        return None
    try:
        client = Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
        client.ping()
        return client
    except Exception:
        return None


def _check_login_rate_limit_shared(settings: Settings, email: str) -> None:
    key = f"nope:auth:login-failures:{hashlib.sha256(_rate_limit_key(email).encode()).hexdigest()}"
    window = max(1, int(settings.login_failure_window_seconds))
    limit = max(1, int(settings.login_failure_limit))
    client = _redis_client(settings)
    if client is None:
        return _check_login_rate_limit(email)
    try:
        attempts = int(client.get(key) or "0")
        if attempts >= limit:
            raise AuthRateLimitError("Too many failed login attempts. Try again later.")
    finally:
        client.close()


def _record_login_failure_shared(settings: Settings, email: str) -> None:
    key = f"nope:auth:login-failures:{hashlib.sha256(_rate_limit_key(email).encode()).hexdigest()}"
    window = max(1, int(settings.login_failure_window_seconds))
    client = _redis_client(settings)
    if client is None:
        return _record_login_failure(email)
    try:
        attempts = client.incr(key)
        if int(attempts) == 1:
            client.expire(key, window)
    finally:
        client.close()


def _clear_login_failure_shared(settings: Settings, email: str) -> None:
    key = f"nope:auth:login-failures:{hashlib.sha256(_rate_limit_key(email).encode()).hexdigest()}"
    client = _redis_client(settings)
    if client is None:
        return _clear_login_failure(email)
    try:
        client.delete(key)
    finally:
        client.close()


def init_auth_db(settings: Settings) -> None:
    run_migrations(settings)


def _hash_password(password: str, salt: bytes | None = None, iterations: int = _PASSWORD_PBKDF2_ITERATIONS) -> str:
    salt = salt or os.urandom(16)
    iterations = max(180_000, int(iterations))
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        if len(parts) == 3:
            _, salt_hex, digest_hex = parts
            iterations = 180_000
        elif len(parts) == 4:
            _, iterations_text, salt_hex, digest_hex = parts
            iterations = int(iterations_text)
        else:
            return False
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations).hex()
    return secrets.compare_digest(candidate, digest_hex)


def _hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_or_login(settings: Settings, email: str, password: str) -> dict:
    normalized = email.strip().lower()
    if not normalized or len(password) < 8:
        raise ValueError("Email is required and password must be at least 8 characters.")
    _check_login_rate_limit_shared(settings, normalized)
    init_auth_db(settings)
    with _connect(settings) as conn:
        user = conn.execute("select * from local_users where email = %s", (normalized,)).fetchone()
        if user is None:
            user_id = f"user_{secrets.token_hex(8)}"
            conn.execute(
                "insert into local_users (id, email, password_hash) values (%s, %s, %s)",
                (user_id, normalized, _hash_password(password, iterations=settings.password_pbkdf2_iterations)),
            )
            user = {"id": user_id, "email": normalized}
        elif not _verify_password(password, user["password_hash"]):
            _record_login_failure_shared(settings, normalized)
            raise PermissionError("Invalid local credentials.")
        _clear_login_failure_shared(settings, normalized)
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        conn.execute(
            "insert into local_sessions (token, user_id, expires_at) values (%s, %s, %s)",
            (_hash_session_token(token), user["id"], expires_at),
        )
        return {"token": token, "user": {"id": user["id"], "email": user["email"]}, "expires_at": expires_at.isoformat()}


def get_user_for_token(settings: Settings, token: str | None) -> dict | None:
    if not token:
        return None
    init_auth_db(settings)
    token_hash = _hash_session_token(token)
    with _connect(settings) as conn:
        row = conn.execute(
            """
            select u.id, u.email, u.created_at
            from local_sessions s
            join local_users u on u.id = s.user_id
            where s.token in (%s, %s) and s.expires_at > now()
            """,
            (token_hash, token),
        ).fetchone()
    return dict(row) if row else None


def delete_session(settings: Settings, token: str | None) -> None:
    if not token:
        return
    init_auth_db(settings)
    token_hash = _hash_session_token(token)
    with _connect(settings) as conn:
        conn.execute("delete from local_sessions where token in (%s, %s)", (token_hash, token))
