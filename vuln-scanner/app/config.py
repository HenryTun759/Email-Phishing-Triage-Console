from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./labvuln.db"
    allow_public_targets: bool = False
    scan_timeout_seconds: float = 8.0
    max_concurrent_scans: int = 4
    app_env: str = "production"
    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    admin_username: str = "admin"
    admin_password: SecretStr
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
