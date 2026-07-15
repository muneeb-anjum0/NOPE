from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NOPE_", env_file=".env", extra="ignore")

    environment: str = "development"
    base_url: str = "http://localhost:8000"
    web_url: str = "http://localhost:3000"
    database_url: str = "postgresql+psycopg://nope:nope@localhost:5432/nope"
    auth_database_url: str = "postgresql://nope:nope@localhost:5432/nope"
    redis_url: str = "redis://localhost:6379/0"
    minio_endpoint: str = "http://localhost:9000"
    session_secret: str = "development-session-secret-change-me"
    encryption_key: str = "development-encryption-key-change-me"
    require_authenticated_api: bool = True

    max_archive_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 200 * 1024 * 1024
    max_file_count: int = 8000
    max_scan_seconds: int = 900
    max_scanner_seconds: int = 180
    max_scanner_output_bytes: int = 2 * 1024 * 1024
    allow_private_url_targets: bool = False
    allow_localhost_url_targets: bool = False
    temp_root: Path = Field(default_factory=lambda: Path.cwd() / ".nope-workspaces")

    ai_provider: str = "none"
    ai_runtime_url: str = "http://localhost:11434"
    ai_model_name: str = "qwen3-8b-q4-k-m"
    ai_model_path: str = "/models/qwen3-8b-q4_k_m.gguf"
    ai_context_length: int = 8192
    ai_max_output_tokens: int = 1024
    ai_temperature: float = 0.1
    ai_top_p: float = 0.9
    ai_gpu_layers: int = 28
    ai_gpu_memory_target_mb: int = 5120
    ai_timeout_seconds: int = 60
    ai_max_concurrent_tasks: int = 1
    ai_max_iterations: int = 2
    ai_max_tool_calls: int = 4
    ai_max_retrieved_chunks: int = 8
    ai_max_repository_tokens: int = 24000

    def validate_production_secrets(self) -> list[str]:
        if self.environment != "production":
            return []
        warnings: list[str] = []
        if "change-me" in self.session_secret:
            warnings.append("NOPE_SESSION_SECRET must be replaced in production.")
        if "change-me" in self.encryption_key:
            warnings.append("NOPE_ENCRYPTION_KEY must be replaced in production.")
        return warnings


@lru_cache
def get_settings() -> Settings:
    return Settings()
