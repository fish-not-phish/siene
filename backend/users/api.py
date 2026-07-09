from ninja import Router
from django.middleware.csrf import get_token
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from .schemas import *
from .models import UserProfile, SiteSettings, PersonalAccessToken
from .auth import session_mfa_auth, admin_session_auth

router = Router(tags=["auth"])

def _sync_oidc_social_app(config: SiteSettings):
    from allauth.socialaccount.models import SocialApp
    from django.contrib.sites.models import Site

    SocialApp.objects.filter(provider='openid_connect').delete()

    if not config.oidc_enabled or not all([config.oidc_provider_type, config.oidc_client_id, config.oidc_server_url]):
        return

    app = SocialApp.objects.create(
        provider='openid_connect',
        provider_id=config.oidc_provider_type,
        name='SSO',
        client_id=config.oidc_client_id,
        secret=config.oidc_client_secret,
        settings={'server_url': config.oidc_server_url},
    )
    app.sites.add(Site.objects.get_current())

# ======================
# CSRF
# ======================

@router.get("/csrf", response=dict)
def get_csrf(request: HttpRequest):
    """
    Fetch CSRF token for frontend (Next.js, etc.)
    """
    return {"csrfToken": get_token(request)}


# ======================
# Auth status
# ======================

@router.get("/status", response=AuthStatusOut)
def auth_status(request: HttpRequest):
    return {"isLoggedIn": request.user.is_authenticated}

@router.get("/me", response=MeOut, auth=session_mfa_auth)
def me(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.auth)
    u = request.auth
    return {
        "id": u.id,
        "username": getattr(u, "get_username")() if hasattr(u, "get_username") else u.username,
        "email": getattr(u, "email", None),
        "first_name": getattr(u, "first_name", None),
        "last_name": getattr(u, "last_name", None),
        "isAdmin": profile.is_admin
    }


@router.post("/change-password", response=MessageOut, auth=session_mfa_auth)
def change_password(request, payload: PasswordChangeIn):
    """Change user password"""
    user = request.auth

    # Verify current password
    if not user.check_password(payload.current_password):
        return {"success": False, "message": "Current password is incorrect"}

    # Validate new password length
    if len(payload.new_password) < 8:
        return {"success": False, "message": "New password must be at least 8 characters"}

    # Set new password
    user.set_password(payload.new_password)
    user.save()

    return {"success": True, "message": "Password changed successfully"}

# ======================
# Site Settings (admin only)
# ======================

def _site_settings_out(config: SiteSettings) -> dict:
    return {
        "allow_registration": config.allow_registration,
        "oidc_enabled": config.oidc_enabled,
        "oidc_provider_type": config.oidc_provider_type,
        "oidc_client_id": config.oidc_client_id,
        "oidc_server_url": config.oidc_server_url,
        "oidc_client_secret_set": bool(config.oidc_client_secret),
        "audit_log_retention_days": config.audit_log_retention_days,
        "job_log_retention_days": config.job_log_retention_days,
        "rescan_batch_size": config.rescan_batch_size,
    }


@router.get("/site-settings", response=SiteSettingsOut, auth=admin_session_auth)
def get_site_settings(request: HttpRequest):
    return _site_settings_out(SiteSettings.get())


@router.patch("/site-settings", response=SiteSettingsOut, auth=admin_session_auth)
def update_site_settings(request: HttpRequest, payload: SiteSettingsIn):
    config = SiteSettings.get()

    if payload.allow_registration is not None:
        config.allow_registration = payload.allow_registration
    if payload.oidc_enabled is not None:
        config.oidc_enabled = payload.oidc_enabled
    if payload.oidc_provider_type is not None:
        config.oidc_provider_type = payload.oidc_provider_type
    if payload.oidc_client_id is not None:
        config.oidc_client_id = payload.oidc_client_id
    if payload.oidc_client_secret is not None:
        config.oidc_client_secret = payload.oidc_client_secret
    if payload.oidc_server_url is not None:
        config.oidc_server_url = payload.oidc_server_url
    if payload.audit_log_retention_days is not None:
        config.audit_log_retention_days = payload.audit_log_retention_days
    if payload.job_log_retention_days is not None:
        config.job_log_retention_days = payload.job_log_retention_days
    if payload.rescan_batch_size is not None:
        config.rescan_batch_size = max(1, payload.rescan_batch_size)

    config.save()
    _sync_oidc_social_app(config)

    return _site_settings_out(config)


# ======================
# Personal Access Tokens
# ======================

@router.get("/tokens", response=list[PATOut], auth=session_mfa_auth)
def list_tokens(request):
    return PersonalAccessToken.objects.filter(user=request.auth)


@router.post("/tokens", response={201: PATCreatedOut}, auth=session_mfa_auth)
def create_token(request, payload: PATIn):
    instance, raw = PersonalAccessToken.create_token(
        user=request.auth,
        name=payload.name,
        expires_at=payload.expires_at,
    )
    return 201, {
        "id": instance.id,
        "name": instance.name,
        "prefix": instance.prefix,
        "created_at": instance.created_at,
        "expires_at": instance.expires_at,
        "last_used_at": instance.last_used_at,
        "token": raw,
    }


@router.delete("/tokens/{token_id}", response=MessageOut, auth=session_mfa_auth)
def revoke_token(request, token_id: int):
    token = get_object_or_404(PersonalAccessToken, id=token_id, user=request.auth)
    token.delete()
    return {"success": True, "message": "Token revoked"}


@router.post("/tokens/{token_id}/rotate", response=PATCreatedOut, auth=session_mfa_auth)
def rotate_token(request, token_id: int):
    """Generate a new secret for an existing PAT, preserving its name and expiry."""
    import secrets as _secrets
    import hashlib as _hashlib
    token = get_object_or_404(PersonalAccessToken, id=token_id, user=request.auth)
    raw = _secrets.token_urlsafe(32)
    token.token_hash = _hashlib.sha256(raw.encode()).hexdigest()
    token.prefix = raw[:8]
    token.last_used_at = None
    token.save(update_fields=['token_hash', 'prefix', 'last_used_at'])
    return {
        "id": token.id,
        "name": token.name,
        "prefix": token.prefix,
        "created_at": token.created_at,
        "expires_at": token.expires_at,
        "last_used_at": token.last_used_at,
        "token": raw,
    }