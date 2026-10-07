from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Unified VPS Control Plane"
    environment: str = "development"
    database_url: str = "postgresql+asyncpg://postgres:postgres@db:5432/unified_vps"
    session_secret: str = ""
    cookie_secure: bool = True
    session_ttl_seconds: int = 60 * 60 * 12

    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    bootstrap_token: str = ""

    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_pool_recycle_seconds: int = 1800
    database_pool_timeout_seconds: float = 5.0

    auto_create_schema: bool = False
    api_docs_enabled: bool = True

    login_rate_limit_attempts: int = 8
    login_rate_limit_window_seconds: int = 600
    login_rate_limit_retry_after_seconds: int = 600

    command_lease_seconds: int = 15 * 60
    command_max_attempts: int = 5

    heartbeat_offline_seconds: int = 120
    max_page_size: int = 100

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def model_post_init(self, __context) -> None:
        env = self.environment.lower().strip()
        if env == "production" and (len(self.session_secret.encode("utf-8")) < 32):
            raise ValueError("SESSION_SECRET must be at least 32 bytes in production")
        if env == "production" and len(self.bootstrap_token.encode("utf-8")) < 32:
            raise ValueError("BOOTSTRAP_TOKEN must be at least 32 bytes in production")
        if env == "production" and len(self.bootstrap_admin_password) < 12:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters in production")
        if env == "production" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true in production")
        if env == "production" and self.auto_create_schema:
            raise ValueError("AUTO_CREATE_SCHEMA must be false in production")
        if env == "production" and self.api_docs_enabled:
            raise ValueError("API_DOCS_ENABLED must be false in production")
        if self.database_url == "postgresql+asyncpg://postgres:postgres@db:5432/unified_vps":
            raise ValueError("DATABASE_URL must be explicitly configured")
        if self.database_pool_size < 1 or self.database_max_overflow < 0 or self.database_pool_timeout_seconds <= 0:
            raise ValueError("database pool settings are invalid")
        if self.session_ttl_seconds < 300:
            raise ValueError("SESSION_TTL_SECONDS is too small")
        if not 1 <= self.login_rate_limit_attempts <= 100:
            raise ValueError("LOGIN_RATE_LIMIT_ATTEMPTS is outside the supported range")
        if not 10 <= self.login_rate_limit_window_seconds <= 3600:
            raise ValueError("LOGIN_RATE_LIMIT_WINDOW_SECONDS is outside the supported range")
        if not 30 <= self.command_lease_seconds <= 24 * 60 * 60:
            raise ValueError("COMMAND_LEASE_SECONDS is outside the supported range")
        if not 1 <= self.command_max_attempts <= 20:
            raise ValueError("COMMAND_MAX_ATTEMPTS is outside the supported range")
        if not 30 <= self.heartbeat_offline_seconds <= 24 * 60 * 60:
            raise ValueError("HEARTBEAT_OFFLINE_SECONDS is outside the supported range")
        if not 1 <= self.max_page_size <= 500:
            raise ValueError("MAX_PAGE_SIZE is outside the supported range")


settings = Settings()
