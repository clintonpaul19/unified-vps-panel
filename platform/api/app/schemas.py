from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    email: EmailStr
    is_active: bool

class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    hostname: str | None = Field(default=None, max_length=255)
    public_ipv4: str | None = None
    public_ipv6: str | None = None

class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    hostname: str | None
    public_ipv4: str | None
    public_ipv6: str | None
    agent_version: str | None
    status: str
    last_seen_at: datetime | None

class CommandCreate(BaseModel):
    command_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,79}$")
    payload: dict = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=200)

class CommandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    server_id: UUID
    command_type: str
    payload: dict
    status: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    result: dict | None

class HeartbeatIn(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    status: str = Field(default="online", pattern=r"^(online|degraded)$")
    metrics: dict = Field(default_factory=dict)

class BootstrapRequest(BaseModel):
    organization_name: str = Field(default="Unified VPS", min_length=1, max_length=120)
