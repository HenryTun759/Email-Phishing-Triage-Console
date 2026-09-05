from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./labvuln.db"
    allow_public_targets: bool = False
    scan_timeout_seconds: float = 8.0
    max_concurrent_scans: int = 4
    app_env: str = "production"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
