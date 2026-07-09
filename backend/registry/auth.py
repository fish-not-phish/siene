"""
Docker Registry Token Auth (JWT RS256).

Reference: https://distribution.github.io/distribution/spec/auth/token/

Django issues a signed JWT when the registry returns 401.
The registry validates the JWT using the public cert configured in
REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE.

Setup:
  1. Generate key pair:
       openssl genrsa -out backend/certs/private.pem 4096
       openssl req -new -x509 -days 3650 -key backend/certs/private.pem \
               -out docker/certs/domain.crt -subj "/CN=harbor-clone"
  2. Set env vars:
       REGISTRY_PRIVATE_KEY_PATH=/path/to/private.pem
       REGISTRY_TOKEN_ISSUER=harbor-clone     (must match docker-compose)
       REGISTRY_TOKEN_SERVICE=registry.local  (must match docker-compose)
"""

import os
import uuid
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from registry.models import Project, RobotAccount
from registry.permissions import can_pull, can_push


def _is_authenticated(user) -> bool:
    """Return True for real Django Users and RobotAccount instances."""
    if user is None:
        return False
    if isinstance(user, RobotAccount):
        return True
    return bool(getattr(user, 'is_authenticated', False))


def _get_subject(user) -> str:
    """Return the subject string for the JWT 'sub' claim."""
    if user is None:
        return 'anonymous'
    if isinstance(user, RobotAccount):
        scope = user.project.name if user.project else 'system'
        return f'robot${scope}+{user.name}'
    return getattr(user, 'username', 'anonymous') or 'anonymous'


_PRIVATE_KEY_PATH = os.environ.get('REGISTRY_PRIVATE_KEY_PATH', '')
_TOKEN_ISSUER = os.environ.get('REGISTRY_TOKEN_ISSUER', 'harbor-clone')
_TOKEN_SERVICE = os.environ.get('REGISTRY_TOKEN_SERVICE', 'registry.local')
_TOKEN_EXPIRY_SECONDS = int(os.environ.get('REGISTRY_TOKEN_EXPIRY', '3600'))


def _load_private_key():
    """Load the RSA private key from disk (cached at module level)."""
    if not _PRIVATE_KEY_PATH:
        return None
    path = Path(_PRIVATE_KEY_PATH)
    if not path.exists():
        return None
    raw = path.read_bytes()
    return load_pem_private_key(raw, password=None)


_private_key = None


def _get_private_key():
    global _private_key
    if _private_key is None:
        _private_key = _load_private_key()
    return _private_key


def _kid_from_key(private_key) -> str:
    """Derive the JWK thumbprint key ID (RFC 7638) from the RSA public key.

    Distribution v3 builds its TrustedKeys map using GetJWKThumbprint(), which
    computes SHA256({"e":"<b64url>","kty":"RSA","n":"<b64url>"}) and encodes it
    as base64url (no padding).  The token's kid header must use the same format
    or the registry rejects it with "token signed by untrusted key".
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    pub = private_key.public_key()
    if not isinstance(pub, RSAPublicKey):
        raise ValueError("Only RSA keys are supported")
    pub_numbers = pub.public_numbers()
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, 'big')
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, 'big')
    e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode()
    n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode()
    # Keys MUST be in lexicographic order per RFC 7638 §3.2
    jwk_json = f'{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}'
    digest = hashlib.sha256(jwk_json.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


def _build_access(scope: str, actions: list[str]) -> dict:
    """Build a single access entry from a scope string like 'repository:myproject/myrepo:pull,push'."""
    parts = scope.split(':')
    resource_type = parts[0] if len(parts) > 0 else 'repository'
    resource_name = parts[1] if len(parts) > 1 else ''
    return {
        'type': resource_type,
        'name': resource_name,
        'actions': actions,
    }


def issue_token(user, scope_string: str | None) -> dict:
    """
    Issue a JWT for the given user and requested scope.

    scope_string examples:
        repository:myproject/myrepo:pull
        repository:myproject/myrepo:pull,push
        registry:catalog:*
    """
    private_key = _get_private_key()
    now = datetime.now(timezone.utc)
    access = []

    if scope_string:
        for scope in scope_string.split(' '):
            parts = scope.split(':')
            if len(parts) != 3:
                continue
            resource_type, resource_name, requested_actions_str = parts
            requested_actions = requested_actions_str.split(',')

            if resource_type == 'repository':
                granted_actions = _check_repo_access(user, resource_name, requested_actions)
                if granted_actions:
                    access.append(_build_access(scope, granted_actions))
            elif resource_type == 'registry' and resource_name == 'catalog':
                # Grant catalog access to Django superusers and to users with
                # UserProfile.is_admin=True.  Django superusers created via
                # createsuperuser may not have a UserProfile row, so we check
                # is_superuser directly before falling back to is_system_admin.
                from registry.permissions import is_system_admin
                _is_admin = False
                if user and _is_authenticated(user):
                    if getattr(user, 'is_superuser', False):
                        _is_admin = True
                    else:
                        try:
                            _is_admin = is_system_admin(user)
                        except Exception:
                            pass
                if _is_admin:
                    access.append(_build_access(scope, ['*']))

    payload = {
        'iss': _TOKEN_ISSUER,
        'sub': _get_subject(user),
        'aud': _TOKEN_SERVICE,
        'exp': int((now + timedelta(seconds=_TOKEN_EXPIRY_SECONDS)).timestamp()),
        'nbf': int(now.timestamp()),
        'iat': int(now.timestamp()),
        'jti': str(uuid.uuid4()),
        'access': access,
    }

    if private_key:
        headers = {'kid': _kid_from_key(private_key)}
        token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    else:
        # Dev fallback: HS256 with a dummy secret (registry won't accept this
        # but it lets the UI boot without certs configured)
        token = jwt.encode(payload, 'dev-secret', algorithm='HS256')

    issued_at = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    return {
        'token': token,
        'access_token': token,
        'expires_in': _TOKEN_EXPIRY_SECONDS,
        'issued_at': issued_at,
    }


def _check_repo_access(user, resource_name: str, requested_actions: list[str]) -> list[str]:
    """Return the subset of requested_actions the user is authorised for."""
    parts = resource_name.split('/', 1)
    if len(parts) < 2:
        return []
    project_name = parts[0]

    try:
        project = Project.objects.get(name=project_name)
    except Project.DoesNotExist:
        return []

    granted = []

    if isinstance(user, RobotAccount):
        # Robot accounts are not Django Users — check their permissions JSON directly.
        # Format: [{"resource": "repository", "action": "pull"}, ...]
        robot_actions = {
            p.get('action')
            for p in (user.permissions or [])
            if p.get('resource') == 'repository'
        }
        if 'pull' in requested_actions and 'pull' in robot_actions:
            granted.append('pull')
        if 'push' in requested_actions and 'push' in robot_actions:
            granted.append('push')
        return granted

    if 'pull' in requested_actions and can_pull(user, project):
        # Content-trust policy (signatures, vulnerability/secret/misconfig
        # pull-prevention) is enforced by the get_token view in api.py, which
        # has access to the full allowlist helpers and per-tag scan results.
        # _check_repo_access is called *after* get_token already rejected
        # blocked requests, so we only need to grant the RBAC-approved action
        # here without duplicating the policy logic.
        granted.append('pull')

    if 'push' in requested_actions and user and _is_authenticated(user) and can_push(user, project):
        granted.append('push')
    if '*' in requested_actions:
        from registry.permissions import is_system_admin
        if user and _is_authenticated(user) and is_system_admin(user):
            granted.append('*')

    return granted
