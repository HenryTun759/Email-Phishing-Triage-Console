from datetime import datetime
from pydantic import BaseModel, Field

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=8, max_length=128)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=80, ge=1, le=65535)
    authorized: bool = False

class TargetOut(TargetCreate):
    id: int
    created_at: datetime
    model_config = {"from_attributes": True}

class ScanCreate(BaseModel):
    target_id: int

class FindingOut(BaseModel):
    id: int
    check_id: str
    title: str
    severity: str
    cvss_score: float | None
    cvss_vector: str | None
    evidence: str
    remediation: str
    model_config = {"from_attributes": True}

class ScanOut(BaseModel):
    id: int
    target_id: int
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    findings: list[FindingOut] = Field(default_factory=list)
    model_config = {"from_attributes": True}
