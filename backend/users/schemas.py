from ninja import Schema
from datetime import datetime
from typing import Optional


class AuthStatusOut(Schema):
    isLoggedIn: bool


class MessageOut(Schema):
    success: bool
    message: str

class MeOut(Schema):
    id: int
    username: str
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    isAdmin: bool


class PasswordChangeIn(Schema):
    current_password: str
    new_password: str


class SiteSettingsOut(Schema):
    allow_registration: bool
    oidc_enabled: bool
    oidc_provider_type: str
    oidc_client_id: str
    oidc_server_url: str
    oidc_client_secret_set: bool
    audit_log_retention_days: int
    job_log_retention_days: int
    rescan_batch_size: int


class SiteSettingsIn(Schema):
    allow_registration: bool | None = None
    oidc_enabled: bool | None = None
    oidc_provider_type: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_server_url: str | None = None
    audit_log_retention_days: int | None = None
    job_log_retention_days: int | None = None
    rescan_batch_size: int | None = None


# ── GC Config ────────────────────────────────────────────────────────────────

class GCConfigOut(Schema):
    gc_enabled: bool
    gc_schedule_type: str
    gc_interval_hours: int
    gc_schedule_time: str
    gc_schedule_day_of_week: int
    gc_schedule_day_of_month: int
    gc_last_run_at: Optional[datetime]


class GCConfigIn(Schema):
    gc_enabled: Optional[bool] = None
    gc_schedule_type: Optional[str] = None
    gc_interval_hours: Optional[int] = None
    gc_schedule_time: Optional[str] = None
    gc_schedule_day_of_week: Optional[int] = None
    gc_schedule_day_of_month: Optional[int] = None


# ── Trivy DB Config ──────────────────────────────────────────────────────────

class TrivyConfigOut(Schema):
    trivy_db_update_enabled: bool
    trivy_db_update_interval_hours: int
    trivy_db_last_updated_at: Optional[datetime]


class TrivyConfigIn(Schema):
    trivy_db_update_enabled: Optional[bool] = None
    trivy_db_update_interval_hours: Optional[int] = None


# ── Personal Access Tokens ────────────────────────────────────────────────────

class PATIn(Schema):
    name: str
    expires_at: Optional[datetime] = None


class PATOut(Schema):
    id: int
    name: str
    prefix: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]


class PATCreatedOut(PATOut):
    """Returned once on creation — includes the plaintext token."""
    token: str
