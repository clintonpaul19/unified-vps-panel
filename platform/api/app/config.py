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
    auto_create_schema: bool = False
    command_lease_seconds: int = 15 * 60
    max_command_payload_bytes: int = 16 * 1024
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def model_post_init(self, __context) -> None:
        if self.environment.lower() == "production" and not self.session_secret:
            raise ValueError("SESSION_SECRET must be configured in production")
        if self.database_pool_size < 1 or self.database_max_overflow < 0:
            raise ValueError("database pool settings are invalid")
        if self.session_ttl_seconds < 300:
            raise ValueError("SESSION_TTL_SECONDS is too small")


settings = Settings()