from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


MAX_JSON_BYTES = 16 * 1024
SUPPORTED_COMMAND_TYPES = frozenset({"service.restart", "health.report"})


def _validate_json_size(value: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    import json
    if len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError(f"{name} is too large")
    return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    email: EmailStr
    is_active: bool


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    slug: str


class ServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    hostname: str | None = Field(default=None, max_length=255)
    public_ipv4: str | None = None
    public_ipv6: str | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("server name is required")
        return value

    @field_validator("public_ipv4")
    @classmethod
    def validate_ipv4(cls, value: str | None) -> str | None:
        if value is not None:
            IPv4Address(value)
        return value

    @field_validator("public_ipv6")
    @classmethod
    def validate_ipv6(cls, value: str | None) -> str | None:
        if value is not None:
            IPv6Address(value)
        return value


class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    hostname: str | None
    public_ipv4: str | None
    public_ipv6: str | None
    agent_version: str | None
    status: str
    metrics: dict
    last_seen_at: datetime | None


class CommandCreate(BaseModel):
    command_type: str = Field(min_length=1, max_length=80)
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=200)

    @field_validator("command_type")
    @classmethod
    def validate_command_type(cls, value: str) -> str:
        value = value.strip()
        if value not in SUPPORTED_COMMAND_TYPES:
            raise ValueError("unsupported command type")
        return value

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_json_size(value, "command payload") or {}

    @field_validator("idempotency_key")
    @classmethod
    def normalize_idempotency_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or any(ord(ch) < 32 for ch in value):
            raise ValueError("invalid idempotency key")
        return value


class CommandResult(BaseModel):
    status: str = Field(pattern=r"^(running|succeeded|failed)$")
    result: dict[str, Any] | None = None
    error: str | None = Field(default=None, max_length=2000)

    @field_validator("result")
    @classmethod
    def validate_result(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_json_size(value, "command result")


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
    lease_until: datetime | None
    attempt_count: int
    error: str | None
    result: dict | None


class HeartbeatIn(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    public_ipv4: str | None = None
    public_ipv6: str | None = None
    status: str = Field(default="online", pattern=r"^(online|degraded)$")
    metrics: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metrics")
    @classmethod
    def validate_metrics(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_json_size(value, "heartbeat metrics") or {}


class BootstrapRequest(BaseModel):
    organization_name: str = Field(default="Unified VPS", min_length=1, max_length=120)

    @field_validator("organization_name")
    @classmethod
    def normalize_organization_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("organization name is required")
        return value
