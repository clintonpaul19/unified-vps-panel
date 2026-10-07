from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "Unified VPS Control Plane"
    environment: str = "development"
    database_url: str = "postgresql+asyncpg://postgres:postgres@db:5432/unified_vps"
    session_secret: str = ""
    cookie_secure: bool = False
    session_ttl_seconds: int = 60 * 60 * 12
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
