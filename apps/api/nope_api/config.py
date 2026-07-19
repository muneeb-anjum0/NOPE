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
    minio_access_key: str = "nope"
    minio_secret_key: str = "nope-development-password"
    minio_bucket: str = "nope-artifacts"
    minio_secure: bool = False
    session_secret: str = "development-session-secret-change-me"
    encryption_key: str = "development-encryption-key-change-me"
    require_authenticated_api: bool = True

    max_archive_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 200 * 1024 * 1024
    max_file_count: int = 8000
    max_archive_path_length: int = 240
    max_archive_nesting_depth: int = 24
    max_archive_compression_ratio: int = 100
    max_scan_seconds: int = 900
    max_scanner_seconds: int = 180
    scanner_concurrency: int = 3
    max_scanner_output_bytes: int = 2 * 1024 * 1024
    allow_private_url_targets: bool = False
    allow_localhost_url_targets: bool = False
    temp_root: Path = Field(default_factory=lambda: Path.cwd() / ".nope-workspaces")

    sandbox_enabled: bool = True
    sandbox_docker_command: str = "docker"
    sandbox_runner_url: str = ""
    sandbox_runner_token: str = "development-runner-token-change-me"
    sandbox_workspace_volume: str = ""
    sandbox_node_image: str = "node:24-alpine"
    sandbox_python_image: str = "python:3.11-slim"
    sandbox_static_image: str = "node:24-alpine"
    sandbox_zap_image: str = "ghcr.io/zaproxy/zaproxy:stable"
    sandbox_timeout_seconds: int = 60
    sandbox_startup_timeout_seconds: int = 20
    sandbox_zap_timeout_seconds: int = 180
    sandbox_memory: str = "512m"
    sandbox_zap_memory: str = "1024m"
    sandbox_cpus: float = 1.0
    sandbox_pids_limit: int = 128
    sandbox_zap_pids_limit: int = 256
    sandbox_tmpfs_size: str = "256m"
    sandbox_log_bytes: int = 64 * 1024
    sandbox_network_enabled: bool = False
    sandbox_allow_images: str = "node:,python:,ghcr.io/zaproxy/zaproxy:"
    sandbox_allow_commands: str = "python -m compileall .,python app.py,python -m http.server 8080,python -m http.server 8080 --bind 0.0.0.0,node server.js,pytest -q,npm test,npm run test,npm run build,pnpm test,pnpm build,yarn test,yarn build"
    url_scan_timeout_seconds: int = 15
    url_scan_max_response_bytes: int = 1024 * 1024
    url_scan_max_redirects: int = 0
    url_scan_allowed_ports: str = "80,443"

    github_api_base_url: str = "https://api.github.com"
    github_oauth_authorize_url: str = "https://github.com/login/oauth/authorize"
    github_oauth_token_url: str = "https://github.com/login/oauth/access_token"
    github_timeout_seconds: int = 20
    github_max_repository_kb: int = 51200
    github_max_archive_bytes: int = 50 * 1024 * 1024
    github_max_file_count: int = 8000
    github_lfs_policy: str = "block"
    github_submodule_policy: str = "block"

    ai_provider: str = "none"
    ai_runtime_url: str = "http://localhost:11434"
    ai_model_name: str = "qwen3-8b-q4-k-m"
    ai_model_path: str = "/models/Qwen3-8B-Q4_K_M.gguf"
    qwen_endpoint: str = "http://localhost:11434"
    qwen_model_file: str = "Qwen3-8B-Q4_K_M.gguf"
    qwen_context_size: int = 4096
    qwen_batch_size: int = 256
    qwen_threads: int = 8
    qwen_parallel: int = 1
    qwen_gpu_layers: int = 28
    qwen_max_output_tokens: int = 1024
    qwen_timeout_seconds: int = 180
    qwen_gpu_memory_target_mb: int = 5000
    qwen_retry_limit: int = 0
    ai_context_length: int = 4096
    ai_max_output_tokens: int = 1024
    ai_temperature: float = 0.1
    ai_top_p: float = 0.9
    ai_gpu_layers: int = 28
    ai_gpu_memory_target_mb: int = 5000
    ai_timeout_seconds: int = 180
    ai_max_concurrent_tasks: int = 1
    ai_max_iterations: int = 2
    ai_max_tool_calls: int = 4
    ai_max_retrieved_chunks: int = 8
    ai_max_repository_tokens: int = 24000
    ai_rag_max_files: int = 8
    ai_rag_max_repository_files: int = 96
    ai_rag_max_file_bytes: int = 240 * 1024
    ai_rag_max_tokens: int = 6000
    ai_rag_graph_depth: int = 2
    ai_rag_chunk_chars: int = 1600

    @property
    def qwen_runtime_url(self) -> str:
        if self.qwen_endpoint != "http://localhost:11434":
            return self.qwen_endpoint
        return self.ai_runtime_url

    @property
    def qwen_model_path(self) -> str:
        if self.ai_model_path != "/models/Qwen3-8B-Q4_K_M.gguf":
            return self.ai_model_path
        return f"/models/{self.qwen_model_file}"

    @property
    def effective_qwen_context_size(self) -> int:
        return min(self.qwen_context_size, self.ai_context_length)

    @property
    def effective_qwen_max_output_tokens(self) -> int:
        return min(self.qwen_max_output_tokens, self.ai_max_output_tokens)

    @property
    def effective_qwen_gpu_layers(self) -> int:
        return min(self.qwen_gpu_layers, self.ai_gpu_layers)

    @property
    def effective_qwen_timeout_seconds(self) -> int:
        return max(1, min(self.qwen_timeout_seconds, self.ai_timeout_seconds))

    @property
    def effective_qwen_gpu_memory_target_mb(self) -> int:
        return min(self.qwen_gpu_memory_target_mb, self.ai_gpu_memory_target_mb, 5000)

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
