from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./labvuln.db"
    allow_public_targets: bool = False
    scan_timeout_seconds: float = Field(default=8.0, gt=0, le=60)
    max_concurrent_scans: int = Field(default=4, ge=1, le=16)
    app_env: str = "production"
    jwt_secret: SecretStr = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = Field(default=30, ge=5, le=240)
    admin_username: str = Field(default="admin", min_length=1, max_length=80)
    admin_password: SecretStr = Field(min_length=12)
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
