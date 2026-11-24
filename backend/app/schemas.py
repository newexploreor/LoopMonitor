from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class HeaderIn(BaseModel):
    name: str
    value: str


class AssertionIn(BaseModel):
    type: Literal["contains", "json_eq"]
    value: str
    path: str | None = None


class MonitorIn(BaseModel):
    name: str
    group_name: str | None = None
    url: str
    method: Literal["GET", "HEAD", "POST"] = "GET"
    headers: list[HeaderIn] = Field(default_factory=list)
    body: str | None = None
    interval_seconds: int | None = None
    timeout_seconds: int | None = None
    expected_status: str = "200-299"
    assertions: list[AssertionIn] = Field(default_factory=list)
    failure_threshold: int = 3
    recovery_threshold: int = 1
    follow_redirects: bool = False
    enabled: bool = True
    channel_ids: list[str] = Field(default_factory=list)


class MonitorPatch(BaseModel):
    name: str | None = None
    group_name: str | None = None
    url: str | None = None
    method: Literal["GET", "HEAD", "POST"] | None = None
    headers: list[HeaderIn] | None = None
    body: str | None = None
    interval_seconds: int | None = None
    timeout_seconds: int | None = None
    expected_status: str | None = None
    assertions: list[AssertionIn] | None = None
    failure_threshold: int | None = None
    recovery_threshold: int | None = None
    follow_redirects: bool | None = None
    enabled: bool | None = None
    channel_ids: list[str] | None = None


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str
    secret: str | None = None
    enabled: bool = True


class ChannelPatch(BaseModel):
    name: str | None = None
    url: str | None = None
    secret: str | None = None
    enabled: bool | None = None


class SettingsPatch(BaseModel):
    check_retention_days: int | None = None
    incident_retention_days: int | None = None
