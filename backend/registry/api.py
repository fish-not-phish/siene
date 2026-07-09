"""
Registry API — all endpoints under /api/registry/
"""

import secrets
import hashlib
import os
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from ninja import Router
from ninja.errors import HttpError
from ninja.security import HttpBasicAuth

from users.auth import session_mfa_auth, admin_session_auth
from users.models import SiteSettings
from users.schemas import GCConfigOut, GCConfigIn, TrivyConfigOut, TrivyConfigIn
from registry.models import (
    GCJob, TrivyUpdateJob,
    Project, ProjectMember, Repository, Tag,
    RobotAccount, AuditLog, VulnerabilityScan, SBOMReport,
    Label, RemoteRegistry, ReplicationRule, ProjectPolicy,
    TagSignatureStatus, SecretScan, MisconfigScan, VulnAllowlistEntry,
    SecretAllowlistEntry, MisconfigAllowlistEntry,
)
from registry.schemas import (
    ProjectIn, ProjectPatchIn, ProjectOut, ProjectSummaryOut,
    MemberIn, MemberPatchIn, MemberOut,
    RepositoryOut, RepositoryPatchIn,
    TagDetailOut, TagLabelIn,
    RobotIn, RobotPatchIn, RobotOut, RobotCreatedOut,
    AuditLogOut,
    SystemStatsOut,
    ScanReportOut, SBOMReportOut,
    SecretScanReportOut, MisconfigScanReportOut,
    LabelIn, LabelPatchIn, LabelOut,
    SignatureStatusOut,
    RemoteRegistryIn, RemoteRegistryPatchIn, RemoteRegistryOut,
    ReplicationRuleIn, ReplicationRulePatchIn, ReplicationRuleOut, ReplicationJobOut,
    VulnSummaryOut, SecretSummaryOut, MisconfigSummaryOut,
    ProjectPolicyOut, ProjectPolicyPatchIn,
    VulnAllowlistIn, VulnAllowlistPatchIn, VulnAllowlistOut,
    SecretAllowlistIn, SecretAllowlistPatchIn, SecretAllowlistOut,
    MisconfigAllowlistIn, MisconfigAllowlistPatchIn, MisconfigAllowlistOut,
    PaginatedTagsOut,
    UserSearchOut,
    CreateUserIn,
    PatchUserIn,
    TokenOut, MessageOut,
    SyncJobOut,
    GCJobOut,
    GcDryRunOut,
    TrivyUpdateJobOut,
    RetentionPreviewIn,
)
from registry.permissions import (
    can_pull, can_push, can_delete, can_manage_members,
    can_manage_project, is_system_admin,
)

router = Router()


def require(condition: bool, status: int = 403, message: str = 'Forbidden') -> None:
    """Raise HttpError if condition is False. Ninja catches these automatically."""
    if not condition:
        raise HttpError(status, message)


def _scan_already_inflight(model_class, tag) -> bool:
    """Return True if there is already a pending or running scan of this type for the tag.

    Used at every dispatch site to guarantee at most one in-flight job per
    (tag, scan_type) pair at any given time.  The concurrency-1 worker ensures
    only one job executes at once; this guard ensures only one job is *queued*
    at once, so we never burn queue slots on redundant work.
    """
    return model_class.objects.filter(
        tag=tag, status__in=('pending', 'running')
    ).exists()


def log_action(
    actor,
    operation: str,
    resource_type: str,
    resource: str,
    detail: dict,
    project=None,
    result: bool = True,
) -> None:
    """Create an AuditLog entry. Swallows exceptions so logging never breaks a request."""
    try:
        if isinstance(actor, RobotAccount):
            scope = actor.project.name if actor.project else 'system'
            username = f'robot${scope}+{actor.name}'
            user_obj = None
        else:
            username = getattr(actor, 'username', '') or ''
            user_obj = actor if isinstance(actor, User) else None
        AuditLog.objects.create(
            user=user_obj,
            username=username,
            project=project,
            resource_type=resource_type,
            resource=resource,
            operation=operation,
            result=result,
            detail=detail,
        )
    except Exception:
        pass


# ── Docker Token Auth ──────────────────────────────────────────────────────────

def _authenticate_user(request, username: str, password: str):
    """
    Authenticate a user by username or email + password, or as a robot account.
    Returns a User/RobotAccount or None.
    """
    from django.contrib.auth import authenticate

    # Try Django authenticate — works if username matches the User.username field
    user = authenticate(request, username=username, password=password)
    if user:
        return user

    # Allauth uses email as the login identifier — try resolving email → username
    if '@' in username:
        try:
            db_user = User.objects.get(email__iexact=username)
            user = authenticate(request, username=db_user.username, password=password)
            if user:
                return user
        except User.DoesNotExist:
            pass
    else:
        # username supplied (not email) — look up by username and re-authenticate
        try:
            db_user = User.objects.get(username__iexact=username)
            user = authenticate(request, username=db_user.username, password=password)
            if user:
                return user
        except User.DoesNotExist:
            pass

    # Personal Access Token check
    from users.models import PersonalAccessToken
    import hashlib as _hashlib
    pat_hash = _hashlib.sha256(password.encode()).hexdigest()
    try:
        pat = PersonalAccessToken.objects.select_related('user').get(token_hash=pat_hash)
        # Verify the username matches (by username or email)
        if pat.user.username == username or pat.user.email.lower() == username.lower():
            from django.utils import timezone as _tz
            if pat.expires_at is None or pat.expires_at > _tz.now():
                pat.last_used_at = _tz.now()
                pat.save(update_fields=['last_used_at'])
                return pat.user
    except PersonalAccessToken.DoesNotExist:
        pass

    # Robot account check
    # Docker sends the full display name: "robot$<project>+<name>" — strip the prefix.
    try:
        from django.utils import timezone as _tz_r
        _robot_name = username
        if '+' in username:
            _robot_name = username.split('+', 1)[1]
        robot = RobotAccount.objects.get(name=_robot_name, disabled=False)
        # Reject expired robot accounts
        if robot.expires_at is not None and robot.expires_at <= _tz_r.now():
            return None
        h = hashlib.sha256(password.encode()).hexdigest()
        if secrets.compare_digest(robot.secret_hash, h):
            return robot
    except RobotAccount.DoesNotExist:
        pass

    return None


class RegistryBasicAuth(HttpBasicAuth):
    def authenticate(self, request, username, password):
        return _authenticate_user(request, username, password)


@router.get('/auth/token', response=TokenOut, auth=None)
def get_token(request, service: str = '', scope: str = ''):
    """Docker Registry v2 token endpoint."""
    from registry.auth import issue_token
    import base64

    user = None
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Basic '):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            username, password = decoded.split(':', 1)
            user = _authenticate_user(request, username, password)
        except Exception:
            pass
        if user is None:
            raise HttpError(401, 'Invalid credentials')

    # ── Quota enforcement ─────────────────────────────────────────────────────
    # Before issuing a push token, check if the target project is over quota.
    # Quota is checked against the sum of size_bytes of all tags in the project.
    if scope:
        for _scope_part in scope.split():
            _parts = _scope_part.split(':')
            if len(_parts) == 3 and _parts[0] == 'repository':
                _actions = set(_parts[2].split(','))
                _repo_full = _parts[1]
                if 'push' in _actions and '/' in _repo_full:
                    _proj_name = _repo_full.split('/', 1)[0]
                    try:
                        _project = Project.objects.get(name=_proj_name)
                        if _project.quota_gb:
                            _used = Tag.objects.filter(
                                repository__project=_project
                            ).aggregate(total=Sum('size_bytes'))['total'] or 0
                            _limit = int(_project.quota_gb * 1024 ** 3)
                            if _used >= _limit:
                                raise HttpError(
                                    429,
                                    f'Project "{_proj_name}" storage quota exceeded '
                                    f'({_project.quota_gb:.1f} GB). '
                                    'Delete unused images or increase the quota before pushing.'
                                )
                    except Project.DoesNotExist:
                        pass

    # ── Vulnerability pull prevention ─────────────────────────────────────────
    # On pull-only scopes, check whether the target tag has a finished scan that
    # violates the project's vuln_block_rules, and deny the token if so.
    if scope and user:
        for _scope_part in scope.split():
            _parts = _scope_part.split(':')
            if len(_parts) == 3 and _parts[0] == 'repository':
                _actions = set(_parts[2].split(','))
                _repo_full = _parts[1]
                if 'pull' in _actions and 'push' not in _actions and '/' in _repo_full:
                    _proj_name, _repo_name = _repo_full.split('/', 1)
                    try:
                        _project = Project.objects.get(name=_proj_name)
                        _policy, _ = ProjectPolicy.objects.get_or_create(project=_project)
                        if _policy.prevent_vulnerable_images and _policy.vuln_block_rules:
                            # Find the tag being pulled (if a specific tag is in scope)
                            # scope format doesn't include the tag name — check all tags
                            # in the repo and block if ANY have a violated scan.
                            # In practice Docker clients request per-tag, so we check
                            # the most-recently-scanned tag row.
                            _scans = VulnerabilityScan.objects.filter(
                                status='finished',
                                tag__repository__project=_project,
                                tag__repository__name=_repo_name,
                            ).order_by('-finished_at').select_related('tag')
                            # de-duplicate: latest scan per tag
                            _seen: set[int] = set()
                            for _scan in _scans:
                                _tid = _scan.tag_id
                                if _tid in _seen:
                                    continue
                                _seen.add(_tid)
                                _summary = dict(_scan.summary or {})
                                # Subtract allowlisted CVEs from severity counts
                                _suppressed = _active_allowlist_ids(_project, tag=_scan.tag)
                                if _suppressed and _scan.report:
                                    _c = _summary.get('critical', 0) or 0
                                    _h = _summary.get('high', 0) or 0
                                    _m = _summary.get('medium', 0) or 0
                                    _l = _summary.get('low', 0) or 0
                                    _c, _h, _m, _l = _apply_allowlist_to_counts(
                                        _scan.report, _suppressed, _c, _h, _m, _l
                                    )
                                    _summary.update({'critical': _c, 'high': _h, 'medium': _m, 'low': _l})
                                for _sev, _max in _policy.vuln_block_rules.items():
                                    if _max is None:
                                        continue
                                    _count = _summary.get(_sev, 0) or 0
                                    if _count > _max:
                                        raise HttpError(
                                            403,
                                            f'Pull blocked: image has {_count} {_sev} '
                                            f'vulnerability/vulnerabilities (max allowed: {_max}).'
                                        )
                    except Project.DoesNotExist:
                        pass

    # ── Secret pull prevention ────────────────────────────────────────────────
    # Block pulls when the latest finished secret scan exceeds the threshold.
    if scope and user:
        for _scope_part in scope.split():
            _parts = _scope_part.split(':')
            if len(_parts) == 3 and _parts[0] == 'repository':
                _actions = set(_parts[2].split(','))
                _repo_full = _parts[1]
                if 'pull' in _actions and 'push' not in _actions and '/' in _repo_full:
                    _proj_name, _repo_name = _repo_full.split('/', 1)
                    try:
                        _project = Project.objects.get(name=_proj_name)
                        _policy, _ = ProjectPolicy.objects.get_or_create(project=_project)
                        if _policy.prevent_secret_images and _policy.secret_block_threshold is not None:
                            _secret_scans = SecretScan.objects.filter(
                                status='finished',
                                tag__repository__project=_project,
                                tag__repository__name=_repo_name,
                            ).order_by('-finished_at').select_related('tag__repository')
                            _seen_s: set[int] = set()
                            for _sscan in _secret_scans:
                                _stid = _sscan.tag_id
                                if _stid in _seen_s:
                                    continue
                                _seen_s.add(_stid)
                                # Count net secret findings after allowlist suppression.
                                # Must iterate per-finding (not per-rule_id) because one
                                # rule_id can fire multiple times across different files.
                                from django.utils import timezone as _tz_s
                                _now_s = _tz_s.now()
                                _suppressed_rules = set(
                                    v.lower() for v in
                                    SecretAllowlistEntry.objects.filter(
                                        models.Q(project=_project, tag__isnull=True) |
                                        models.Q(tag_id=_stid)
                                    ).filter(
                                        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now_s)
                                    ).values_list('rule_id', flat=True)
                                )
                                _secret_report = _sscan.report or []
                                _net_total = 0
                                for _sfinding in _secret_report:
                                    _rid = (_sfinding.get('rule_id') or '').lower()
                                    if _rid not in _suppressed_rules:
                                        _net_total += 1
                                if _net_total > _policy.secret_block_threshold:
                                    raise HttpError(
                                        403,
                                        f'Pull blocked: image has {_net_total} secret(s) detected '
                                        f'(max allowed: {_policy.secret_block_threshold}).'
                                    )
                    except Project.DoesNotExist:
                        pass

    # ── Misconfig pull prevention ─────────────────────────────────────────────
    # Block pulls when the latest finished misconfig scan has more FAIL findings
    # than the project's misconfig_fail_threshold (after subtracting suppressions).
    if scope and user:
        for _scope_part in scope.split():
            _parts = _scope_part.split(':')
            if len(_parts) == 3 and _parts[0] == 'repository':
                _actions = set(_parts[2].split(','))
                _repo_full = _parts[1]
                if 'pull' in _actions and 'push' not in _actions and '/' in _repo_full:
                    _proj_name, _repo_name = _repo_full.split('/', 1)
                    try:
                        _project = Project.objects.get(name=_proj_name)
                        _policy, _ = ProjectPolicy.objects.get_or_create(project=_project)
                        if _policy.prevent_misconfig_images and _policy.misconfig_fail_threshold is not None:
                            _mc_scans = MisconfigScan.objects.filter(
                                status='finished',
                                tag__repository__project=_project,
                                tag__repository__name=_repo_name,
                            ).order_by('-finished_at').select_related('tag__repository')
                            _seen_m: set[int] = set()
                            for _mcscan in _mc_scans:
                                _mtid = _mcscan.tag_id
                                if _mtid in _seen_m:
                                    continue
                                _seen_m.add(_mtid)
                                from django.utils import timezone as _tz_m
                                _now_m = _tz_m.now()
                                _suppressed_mc = set(
                                    v.lower() for v in
                                    MisconfigAllowlistEntry.objects.filter(
                                        models.Q(project=_project, tag__isnull=True) |
                                        models.Q(tag_id=_mtid)
                                    ).filter(
                                        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now_m)
                                    ).values_list('check_id', flat=True)
                                )
                                # Count net FAIL findings (after allowlist suppression)
                                _mc_report = _mcscan.report or []
                                _fail_count = 0
                                for _finding in _mc_report:
                                    _cid = (_finding.get('check_id') or _finding.get('avd_id') or '').lower()
                                    _level = (_finding.get('level') or _finding.get('severity') or '').upper()
                                    if _level == 'FAIL' and _cid not in _suppressed_mc:
                                        _fail_count += 1
                                if _fail_count > _policy.misconfig_fail_threshold:
                                    raise HttpError(
                                        403,
                                        f'Pull blocked: image has {_fail_count} FAIL misconfig finding(s) '
                                        f'(max allowed: {_policy.misconfig_fail_threshold}).'
                                    )
                    except Project.DoesNotExist:
                        pass

    token_response = issue_token(user, scope or None)

    # Log pull events and increment pull_count at token-issue time — this is
    # where real docker pulls authenticate via Basic auth. Gating on Basic auth
    # excludes all internal callers: scan workers call issue_token() directly
    # in Python (no HTTP request), and the webhook self-fetches use Bearer tokens.
    if user and scope and auth_header.startswith('Basic '):
        from django.db.models import F as _F
        for _scope_part in scope.split():
            # scope format: "repository:project/repo:actions"
            _parts = _scope_part.split(':')
            if len(_parts) == 3 and _parts[0] == 'repository':
                _actions = set(_parts[2].split(','))
                _repo_full = _parts[1]
                if 'pull' in _actions and 'push' not in _actions and '/' in _repo_full:
                    _proj_name, _repo_name = _repo_full.split('/', 1)
                    try:
                        _project = Project.objects.get(name=_proj_name)
                        log_action(
                            user,
                            operation='pull',
                            resource_type='image',
                            resource=_repo_full,
                            detail={'scope': _scope_part},
                            project=_project,
                        )
                        # Increment pull_count here rather than in the webhook
                        # handler so that internal registry fetches (scans,
                        # manifest lookups) are never counted as real pulls.
                        Repository.objects.filter(
                            project=_project, name=_repo_name
                        ).update(pull_count=_F('pull_count') + 1)
                        # Stamp last_activity_at on all tags in the repo —
                        # we don't know which specific tag was pulled from
                        # the scope alone, so update at repo granularity.
                        Tag.objects.filter(
                            repository__project=_project,
                            repository__name=_repo_name,
                        ).update(last_activity_at=timezone.now())
                    except Project.DoesNotExist:
                        pass

    return token_response


# ── Registry Event Webhook ─────────────────────────────────────────────────────

@router.post('/events/', auth=None, response=MessageOut)
def registry_events(request):
    """Receives push/delete notifications from registry:2.

    Auth is checked synchronously here (it's cheap — just a string comparison),
    then the raw body is handed off to a Celery task so the webhook response is
    returned immediately without blocking a Gunicorn worker for manifest fetches,
    DB writes, or scan dispatch.
    """
    import json

    expected = f"Bearer {__import__('os').environ.get('REGISTRY_INTERNAL_TOKEN', '')}"
    auth = request.headers.get('Authorization', '')
    if expected and auth != expected:
        raise HttpError(403, 'Unauthorized')

    try:
        raw_body = request.body.decode('utf-8')
        json.loads(raw_body)  # validate JSON before queuing
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HttpError(400, 'Invalid JSON')

    from registry.tasks import process_registry_events
    process_registry_events.apply_async(args=[raw_body], queue='default')

    return {'success': True, 'message': 'queued'}


def _process_registry_events_sync(raw_body: str) -> None:
    """Process registry push/delete events. Called from the Celery task."""
    import json

    payload = json.loads(raw_body)

    for event in payload.get('events', []):
        action = event.get('action')
        target = event.get('target', {})
        repo_full = target.get('repository', '')
        tag_name = target.get('tag', '')
        digest = target.get('digest', '')
        size = target.get('size', 0)
        actor_name = event.get('actor', {}).get('name', '') or ''

        if not repo_full or '/' not in repo_full:
            continue

        project_name, repo_name = repo_full.split('/', 1)

        try:
            project = Project.objects.get(name=project_name)
        except Project.DoesNotExist:
            continue

        # For delete events, never recreate a repo that was just removed.
        if action == 'delete':
            repo = Repository.objects.filter(project=project, name=repo_name).first()
            if not repo:
                continue
        else:
            repo, _ = Repository.objects.get_or_create(project=project, name=repo_name)

        # Resolve actor to a User object (may be None for anonymous/robot pulls)
        try:
            actor_user = User.objects.get(username=actor_name) if actor_name else None
        except User.DoesNotExist:
            actor_user = None

        class _Actor:
            """Minimal actor shim so log_action works without a real User object."""
            username = actor_name

        if action in ('push', 'pull') and tag_name:
            if action == 'pull':
                # pull_count is now incremented at the token endpoint (get_token)
                # where it is correctly gated on Basic auth, excluding all internal
                # callers (scan workers, webhook self-fetches, etc.).
                pass

            # Fetch the manifest from the registry to detect whether this is a
            # manifest list / OCI index (multi-arch) or a regular single-arch image.
            # Must use a JWT (the registry doesn't accept Basic auth directly).
            manifest_json = {}
            _is_index = False
            _index_manifest_data = {}
            _platform_entries = []   # list of dicts: {digest, os, arch, variant, size}
            try:
                import requests as _req
                from django.contrib.auth.models import User as _User
                from registry.auth import issue_token as _issue_token
                registry_base = __import__('os').environ.get('REGISTRY_INTERNAL_URL', 'http://localhost:5000')
                _scope = f'repository:{repo_full}:pull'
                _admin = _User.objects.filter(is_superuser=True).first()
                _tok = _issue_token(_admin, _scope)['token']
                _headers = {
                    'Accept': (
                        'application/vnd.docker.distribution.manifest.v2+json,'
                        'application/vnd.oci.image.manifest.v1+json,'
                        'application/vnd.oci.image.index.v1+json,'
                        'application/vnd.docker.distribution.manifest.list.v2+json'
                    ),
                    'Authorization': f'Bearer {_tok}',
                }
                mresp = _req.get(
                    f'{registry_base}/v2/{repo_full}/manifests/{digest}',
                    headers=_headers,
                    timeout=10,
                )
                if mresp.ok:
                    _mdata = mresp.json()
                    _media_type = (
                        _mdata.get('mediaType') or
                        mresp.headers.get('Content-Type', '')
                    )
                    _is_index = (
                        'image.index' in _media_type or
                        'manifest.list' in _media_type
                    )
                    if _is_index:
                        _index_manifest_data = _mdata
                        # Collect all platform entries for per-platform child tags
                        for _m in _mdata.get('manifests', []):
                            _plat = _m.get('platform', {})
                            _p_os = _plat.get('os', '')
                            _p_arch = _plat.get('architecture', '')
                            _p_variant = _plat.get('variant', '')
                            # Skip attestation / unknown pseudo-entries
                            if not _p_os or not _p_arch or _p_os == 'unknown':
                                continue
                            _platform_entries.append({
                                'digest': _m['digest'],
                                'os': _p_os,
                                'arch': _p_arch,
                                'variant': _p_variant,
                                'size': _m.get('size', 0),
                            })
                    else:
                        manifest_json = _mdata
            except Exception as _me:
                import logging as _log
                _log.getLogger(__name__).warning('webhook: failed to fetch manifest for %s@%s: %s', repo_full, digest, _me)

            # ── Tag immutability enforcement (applies to the index/root tag name)──
            if action == 'push':
                _existing_tag = Tag.objects.filter(repository=repo, name=tag_name).first()
                if _existing_tag:
                    _policy_imm, _ = ProjectPolicy.objects.get_or_create(project=project)
                    if _policy_imm.tag_immutability:
                        if digest and digest != _existing_tag.digest:
                            _registry_delete_tag_ref(repo_full, tag_name)
                            _registry_delete_manifest(repo_full, digest)
                            _restore_tag_pointer(repo_full, tag_name, _existing_tag.digest)
                        import logging as _log_imm
                        _log_imm.getLogger(__name__).warning(
                            'webhook: immutability blocked overwrite of %s:%s',
                            repo_full, tag_name,
                        )
                        continue  # skip update_or_create and all downstream tasks

            if action == 'push':
                repo.push_count += 1
                repo.save(update_fields=['push_count', 'updated_at'])

            # ── Helper: fetch config blob → (os, arch, image_config) ─────────
            def _fetch_config(child_manifest, tok=None):
                _cfg_digest = child_manifest.get('config', {}).get('digest')
                if not _cfg_digest:
                    return '', '', {}
                try:
                    _r = _req.get(
                        f'{registry_base}/v2/{repo_full}/blobs/{_cfg_digest}',
                        headers={
                            'Authorization': f'Bearer {tok or _tok}',
                            'Accept': 'application/vnd.oci.image.config.v1+json,application/json',
                        },
                        timeout=10,
                    )
                    if _r.ok:
                        _c = _r.ok and _r.json()
                        _c_os   = _c.get('os', '') or ''
                        _c_arch = _c.get('architecture', '') or ''
                        _c_var  = _c.get('variant', '') or ''
                        if _c_var:
                            _c_arch = f'{_c_arch}/{_c_var}'
                        return _c_os, _c_arch, _c
                except Exception:
                    pass
                return '', '', {}

            now_ts = timezone.now()

            if _is_index:
                # ── MULTI-ARCH path ───────────────────────────────────────────
                # 1. Create/update the index Tag row (no scans, no SBOM here).
                _index_defaults = {
                    'digest': digest,
                    'size_bytes': size,
                    'is_index': True,
                    'index_manifest': _index_manifest_data,
                    'last_activity_at': now_ts,
                }
                if action == 'push' and actor_user:
                    _index_defaults['pushed_by'] = actor_user
                if action == 'push':
                    _index_defaults['pushed_at'] = now_ts

                index_tag, _ = Tag.objects.update_or_create(
                    repository=repo,
                    name=tag_name,
                    defaults=_index_defaults,
                )

                if action == 'push':
                    log_action(
                        actor_user or _Actor(),
                        operation='push',
                        resource_type='image',
                        resource=f'{repo_full}:{tag_name}',
                        detail={'digest': digest, 'size': size, 'multi_arch': True},
                        project=project,
                    )

                # 2. Create/update one child Tag per platform, dispatch scans.
                if action == 'push':
                    try:
                        from registry.tasks import (
                            run_combined_scan, run_sbom, run_replication,
                            run_signature_check,
                        )
                        policy, _ = ProjectPolicy.objects.get_or_create(project=project)
                        import fnmatch as _fnmatch

                        for _pe in _platform_entries:
                            _p_os      = _pe['os']
                            _p_arch    = _pe['arch']
                            _p_variant = _pe['variant']
                            _p_digest  = _pe['digest']

                            # Platform string: "linux/amd64" or "linux/arm64/v8"
                            _platform_str = f'{_p_os}/{_p_arch}'
                            if _p_variant:
                                _platform_str = f'{_platform_str}/{_p_variant}'

                            # Child tag name: e.g. "latest@linux/amd64"
                            # We replace '/' with '_' in the platform part so the
                            # name satisfies the registry's tag naming rules and
                            # our unique_together constraint.
                            _child_name = f'{tag_name}@{_platform_str.replace("/", "_")}'

                            # Fetch the child manifest
                            try:
                                _cresp_child = _req.get(
                                    f'{registry_base}/v2/{repo_full}/manifests/{_p_digest}',
                                    headers=_headers,
                                    timeout=10,
                                )
                                _child_manifest = _cresp_child.json() if _cresp_child.ok else {}
                            except Exception:
                                _child_manifest = {}

                            _child_size = sum(
                                l.get('size', 0) for l in _child_manifest.get('layers', [])
                            ) if _child_manifest.get('layers') else _pe['size']

                            _c_os, _c_arch_full, _c_image_config = _fetch_config(_child_manifest)
                            # Prefer config-derived os/arch; fall back to index platform entry
                            if not _c_os:
                                _c_os = _p_os
                            if not _c_arch_full:
                                _c_arch_full = _p_arch
                                if _p_variant:
                                    _c_arch_full = f'{_p_arch}/{_p_variant}'

                            _child_defaults = {
                                'digest': _p_digest,
                                'size_bytes': _child_size,
                                'os': _c_os,
                                'architecture': _c_arch_full,
                                'is_index': False,
                                'parent_tag': index_tag,
                                'platform': _platform_str,
                                'last_activity_at': now_ts,
                                'pushed_at': now_ts,
                            }
                            if _child_manifest:
                                _child_defaults['manifest'] = _child_manifest
                            if _c_image_config:
                                _child_defaults['image_config'] = _c_image_config
                            if actor_user:
                                _child_defaults['pushed_by'] = actor_user

                            child_tag, _ = Tag.objects.update_or_create(
                                repository=repo,
                                name=_child_name,
                                defaults=_child_defaults,
                            )

                            # Dispatch scans for this platform child
                            _vuln_id = _secret_id = _misconfig_id = None
                            if policy.scanning_enabled and not _scan_already_inflight(VulnerabilityScan, child_tag):
                                _vuln_id = VulnerabilityScan.objects.create(tag=child_tag).id
                            if policy.secret_scanning_enabled and not _scan_already_inflight(SecretScan, child_tag):
                                _secret_id = SecretScan.objects.create(tag=child_tag).id
                            if policy.misconfig_scanning_enabled and not _scan_already_inflight(MisconfigScan, child_tag):
                                _misconfig_id = MisconfigScan.objects.create(tag=child_tag).id

                            if _vuln_id or _secret_id or _misconfig_id:
                                run_combined_scan.apply_async(
                                    kwargs={
                                        'vuln_scan_id': _vuln_id,
                                        'secret_scan_id': _secret_id,
                                        'misconfig_scan_id': _misconfig_id,
                                    },
                                    queue='scans',
                                )

                            if policy.sbom_enabled and not _scan_already_inflight(SBOMReport, child_tag):
                                sbom_row = SBOMReport.objects.create(tag=child_tag)
                                run_sbom.apply_async(args=[sbom_row.id], queue='sbom')

                            # Signature check on each child digest
                            run_signature_check.apply_async(args=[child_tag.id], queue='default')

                        # Replication fires on the index tag (whole manifest list)
                        on_push_rules = ReplicationRule.objects.filter(
                            trigger=ReplicationRule.TRIGGER_PUSH,
                            direction=ReplicationRule.DIRECTION_PUSH,
                            enabled=True,
                        )
                        for rule in on_push_rules:
                            if rule.source_filter and not _fnmatch.fnmatch(repo_full, rule.source_filter):
                                continue
                            if rule.tag_filter and not _fnmatch.fnmatch(tag_name, rule.tag_filter):
                                continue
                            run_replication.apply_async(args=[rule.id], kwargs={'tag_id': index_tag.id}, queue='default')

                    except Exception:
                        pass  # Never let task dispatch failures break the webhook response

            else:
                # ── SINGLE-ARCH path (original logic) ─────────────────────────
                # Prefer layer-sum from manifest; fall back to webhook manifest size
                computed_size = size
                if isinstance(manifest_json, dict) and manifest_json.get('layers'):
                    computed_size = sum(
                        layer.get('size', 0) for layer in manifest_json['layers']
                    )

                computed_os, computed_arch, computed_image_config = _fetch_config(manifest_json)

                defaults = {
                    'digest': digest,
                    'size_bytes': computed_size,
                    'os': computed_os,
                    'architecture': computed_arch,
                    'is_index': False,
                    'last_activity_at': now_ts,
                }
                if isinstance(manifest_json, dict) and manifest_json:
                    defaults['manifest'] = manifest_json
                if computed_image_config:
                    defaults['image_config'] = computed_image_config
                if action == 'push' and actor_user:
                    defaults['pushed_by'] = actor_user
                if action == 'push':
                    defaults['pushed_at'] = now_ts

                tag, _ = Tag.objects.update_or_create(
                    repository=repo,
                    name=tag_name,
                    defaults=defaults,
                )

                if action == 'push':
                    log_action(
                        actor_user or _Actor(),
                        operation='push',
                        resource_type='image',
                        resource=f'{repo_full}:{tag_name}',
                        detail={'digest': digest, 'size': size},
                        project=project,
                    )

                if action == 'push':
                    try:
                        from registry.tasks import (
                            run_combined_scan, run_sbom, run_replication,
                            run_signature_check,
                        )
                        policy, _ = ProjectPolicy.objects.get_or_create(project=project)

                        _vuln_id = _secret_id = _misconfig_id = None
                        if policy.scanning_enabled and not _scan_already_inflight(VulnerabilityScan, tag):
                            _vuln_id = VulnerabilityScan.objects.create(tag=tag).id
                        if policy.secret_scanning_enabled and not _scan_already_inflight(SecretScan, tag):
                            _secret_id = SecretScan.objects.create(tag=tag).id
                        if policy.misconfig_scanning_enabled and not _scan_already_inflight(MisconfigScan, tag):
                            _misconfig_id = MisconfigScan.objects.create(tag=tag).id

                        if _vuln_id or _secret_id or _misconfig_id:
                            run_combined_scan.apply_async(
                                kwargs={
                                    'vuln_scan_id': _vuln_id,
                                    'secret_scan_id': _secret_id,
                                    'misconfig_scan_id': _misconfig_id,
                                },
                                queue="scans",
                            )

                        if policy.sbom_enabled and not _scan_already_inflight(SBOMReport, tag):
                            sbom_row = SBOMReport.objects.create(tag=tag)
                            run_sbom.apply_async(args=[sbom_row.id], queue="sbom")

                        run_signature_check.apply_async(args=[tag.id], queue="default")

                        import fnmatch as _fnmatch
                        on_push_rules = ReplicationRule.objects.filter(
                            trigger=ReplicationRule.TRIGGER_PUSH,
                            direction=ReplicationRule.DIRECTION_PUSH,
                            enabled=True,
                        )
                        for rule in on_push_rules:
                            if rule.source_filter and not _fnmatch.fnmatch(repo_full, rule.source_filter):
                                continue
                            if rule.tag_filter and not _fnmatch.fnmatch(tag_name, rule.tag_filter):
                                continue
                            run_replication.apply_async(args=[rule.id], kwargs={'tag_id': tag.id}, queue="default")
                    except Exception:
                        pass

        elif action == 'delete':
            if tag_name:
                Tag.objects.filter(repository=repo, name=tag_name).delete()
                log_action(
                    actor_user or _Actor(),
                    operation='delete',
                    resource_type='image',
                    resource=f'{repo_full}:{tag_name}',
                    detail={'digest': digest},
                    project=project,
                )
            else:
                Repository.objects.filter(id=repo.id).delete()
                log_action(
                    actor_user or _Actor(),
                    operation='delete',
                    resource_type='repository',
                    resource=repo_full,
                    detail={},
                    project=project,
                )



# ── Projects ───────────────────────────────────────────────────────────────────

@router.get('/projects', response=list[ProjectOut], auth=session_mfa_auth)
def list_projects(request):
    user = request.auth
    if is_system_admin(user):
        return Project.objects.all()
    member_ids = ProjectMember.objects.filter(user=user).values_list('project_id', flat=True)
    public_ids = Project.objects.filter(public=True).values_list('id', flat=True)
    return Project.objects.filter(id__in=list(member_ids) + list(public_ids)).distinct()


@router.post('/projects', response={201: ProjectOut}, auth=session_mfa_auth)
def create_project(request, payload: ProjectIn):
    user = request.auth
    project = Project.objects.create(
        name=payload.name,
        display_name=payload.display_name,
        description=payload.description,
        public=payload.public,
        quota_gb=payload.quota_gb,
        owner=user,
    )
    ProjectMember.objects.create(project=project, user=user, role=ProjectMember.ROLE_ADMIN)
    log_action(user, 'create', 'project', payload.name, {
        'name': payload.name,
        'public': payload.public,
    })
    return 201, project


@router.get('/projects/{project_name}', response=ProjectOut, auth=session_mfa_auth)
def get_project(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return project


@router.patch('/projects/{project_name}', response=ProjectOut, auth=session_mfa_auth)
def update_project(request, project_name: str, payload: ProjectPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return project
    for field, value in changes.items():
        setattr(project, field, value)
    project.save()
    log_action(request.auth, 'update', 'project', project_name, {'changes': changes}, project=project)
    return project


@router.delete('/projects/{project_name}', response=MessageOut, auth=session_mfa_auth)
def delete_project(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    log_action(request.auth, 'delete', 'project', project_name, {'name': project_name})
    project.delete()
    return {'success': True, 'message': f'Project {project_name} deleted'}


@router.get('/projects/{project_name}/summary', response=ProjectSummaryOut, auth=session_mfa_auth)
def project_summary(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo_count = project.repositories.count()
    tag_count = Tag.objects.filter(repository__project=project).count()
    storage = Tag.objects.filter(repository__project=project).aggregate(total=Sum('size_bytes'))['total'] or 0
    return {'repo_count': repo_count, 'tag_count': tag_count, 'storage_bytes': storage}


# ── Members ────────────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/members', response=list[MemberOut], auth=session_mfa_auth)
def list_members(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return project.members.select_related('user').all()


@router.post('/projects/{project_name}/members', response={201: MemberOut}, auth=session_mfa_auth)
def add_member(request, project_name: str, payload: MemberIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    user = get_object_or_404(User, username=payload.username)
    member, created = ProjectMember.objects.get_or_create(
        project=project, user=user, defaults={'role': payload.role}
    )
    if not created:
        raise HttpError(409, 'User is already a member of this project')
    log_action(request.auth, 'create', 'member', payload.username,
               {'username': payload.username, 'role': payload.role}, project=project)
    return 201, member


@router.patch('/projects/{project_name}/members/{member_id}', response=MemberOut, auth=session_mfa_auth)
def update_member(request, project_name: str, member_id: int, payload: MemberPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    member = get_object_or_404(ProjectMember, id=member_id, project=project)
    old_role = member.role
    if member.role == payload.role:
        return member
    member.role = payload.role
    member.save()
    log_action(request.auth, 'update', 'member', member.user.username,
               {'username': member.user.username, 'old_role': old_role, 'new_role': payload.role},
               project=project)
    return member


@router.delete('/projects/{project_name}/members/{member_id}', response=MessageOut, auth=session_mfa_auth)
def remove_member(request, project_name: str, member_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    member = get_object_or_404(ProjectMember, id=member_id, project=project)
    log_action(request.auth, 'delete', 'member', member.user.username,
               {'username': member.user.username, 'role': member.role}, project=project)
    member.delete()
    return {'success': True, 'message': 'Member removed'}


# ── Repositories ───────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/repositories', response=list[RepositoryOut], auth=session_mfa_auth)
def list_repositories(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return project.repositories.all()


@router.get('/projects/{project_name}/repositories/{repo_name}', response=RepositoryOut, auth=session_mfa_auth)
def get_repository(request, project_name: str, repo_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return get_object_or_404(Repository, project=project, name=repo_name)


@router.patch('/projects/{project_name}/repositories/{repo_name}', response=RepositoryOut, auth=session_mfa_auth)
def update_repository(request, project_name: str, repo_name: str, payload: RepositoryPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return repo
    if payload.description is not None:
        repo.description = payload.description
        repo.save()
    log_action(request.auth, 'update', 'repository', repo_name, {'changes': changes}, project=project)
    return repo


def _registry_delete_tag_ref(repo_full_name: str, tag_name: str) -> bool:
    """Issue DELETE /v2/{name}/manifests/{tag} to remove the tag name reference.

    Docker Distribution stores tag references separately from manifest blobs.
    Deleting by digest removes the blob but leaves the tag pointer, so the tag
    continues to appear in /tags/list and gets recreated by catalog sync.
    Deleting by tag name removes the pointer first.

    Returns True on success (202/204) or already gone (404), False on error.
    """
    import os
    import requests as _req
    from registry.auth import issue_token as _issue_token
    from django.contrib.auth.models import User as _User

    registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://localhost:5000')
    try:
        _admin = _User.objects.filter(is_superuser=True).first()
        if _admin is None:
            from users.models import UserProfile as _UP
            _profile = _UP.objects.filter(is_admin=True).select_related('user').first()
            if _profile:
                _admin = _profile.user
        _scope = f'repository:{repo_full_name}:*'
        _tok = _issue_token(_admin, _scope)['token']
        resp = _req.delete(
            f'{registry_base}/v2/{repo_full_name}/manifests/{tag_name}',
            headers={
                'Authorization': f'Bearer {_tok}',
                'Accept': (
                    'application/vnd.docker.distribution.manifest.v2+json,'
                    'application/vnd.docker.distribution.manifest.list.v2+json,'
                    'application/vnd.oci.image.manifest.v1+json,'
                    'application/vnd.oci.image.index.v1+json,'
                    '*/*'
                ),
            },
            timeout=10,
        )
        return resp.status_code in (202, 204, 404)
    except Exception:
        return False


def _registry_delete_manifest(repo_full_name: str, digest: str) -> bool:
    """Issue DELETE /v2/{name}/manifests/{digest} to Docker Distribution.

    Returns True on success (204) or if the manifest was already gone (404).
    Returns False on any other error so callers can log but still proceed.
    """
    import os
    import requests as _req
    from registry.auth import issue_token as _issue_token
    from django.contrib.auth.models import User as _User

    registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://localhost:5000')
    try:
        _admin = _User.objects.filter(is_superuser=True).first()
        if _admin is None:
            from users.models import UserProfile as _UP
            _profile = _UP.objects.filter(is_admin=True).select_related('user').first()
            if _profile:
                _admin = _profile.user
        _scope = f'repository:{repo_full_name}:*'
        _tok = _issue_token(_admin, _scope)['token']
        resp = _req.delete(
            f'{registry_base}/v2/{repo_full_name}/manifests/{digest}',
            headers={'Authorization': f'Bearer {_tok}',
                     'Accept': 'application/vnd.docker.distribution.manifest.v2+json,'
                               'application/vnd.docker.distribution.manifest.list.v2+json,'
                               'application/vnd.oci.image.manifest.v1+json,'
                               'application/vnd.oci.image.index.v1+json,'
                               '*/*'},
            timeout=10,
        )
        return resp.status_code in (202, 204, 404)
    except Exception:
        return False


def _restore_tag_pointer(repo_full_name: str, tag_name: str, digest: str) -> bool:
    """Re-associate a tag name with an existing manifest digest in Distribution.

    After an immutability rollback we delete the new manifest by tag name (which
    removes the tag pointer) then delete the orphaned blob by digest.  That leaves
    the tag entirely absent from the registry even though the old manifest blob is
    still present.  This helper PUTs the old manifest content back under the tag
    name so that ``docker pull repo:tag`` continues to work.

    Returns True on success (201/200), False on any error.
    """
    import os
    import requests as _req
    from registry.auth import issue_token as _issue_token
    from django.contrib.auth.models import User as _User

    registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://localhost:5000')
    try:
        _admin = _User.objects.filter(is_superuser=True).first()
        if _admin is None:
            from users.models import UserProfile as _UP
            _profile = _UP.objects.filter(is_admin=True).select_related('user').first()
            if _profile:
                _admin = _profile.user
        _scope = f'repository:{repo_full_name}:*'
        _tok = _issue_token(_admin, _scope)['token']
        auth_headers = {'Authorization': f'Bearer {_tok}'}
        accept = (
            'application/vnd.docker.distribution.manifest.v2+json,'
            'application/vnd.docker.distribution.manifest.list.v2+json,'
            'application/vnd.oci.image.manifest.v1+json,'
            'application/vnd.oci.image.index.v1+json,'
            '*/*'
        )
        # Fetch the raw manifest content by digest
        get_resp = _req.get(
            f'{registry_base}/v2/{repo_full_name}/manifests/{digest}',
            headers={**auth_headers, 'Accept': accept},
            timeout=10,
        )
        if get_resp.status_code != 200:
            return False
        content_type = get_resp.headers.get(
            'Content-Type',
            'application/vnd.docker.distribution.manifest.v2+json',
        )
        # PUT it back under the tag name to restore the tag → digest pointer
        put_resp = _req.put(
            f'{registry_base}/v2/{repo_full_name}/manifests/{tag_name}',
            headers={**auth_headers, 'Content-Type': content_type},
            data=get_resp.content,
            timeout=10,
        )
        return put_resp.status_code in (200, 201)
    except Exception:
        return False


@router.delete('/projects/{project_name}/repositories/{repo_name}', response=MessageOut, auth=session_mfa_auth)
def delete_repository(request, project_name: str, repo_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_delete(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    repo_full = f'{project_name}/{repo_name}'
    # Step 1: remove every tag name reference so the tag stops appearing in
    # /tags/list and cannot be recreated by catalog sync (filesystem and S3).
    # If any tag-pointer delete fails, abort the entire operation so that the
    # registry and DB stay in sync — a partial delete would leave stale pointers
    # that catalog sync would later use to resurrect the deleted repository.
    failed_tags = []
    for tag_obj in repo.tags.all():
        if not _registry_delete_tag_ref(repo_full, tag_obj.name):
            failed_tags.append(tag_obj.name)
    if failed_tags:
        raise HttpError(
            502,
            f'Registry error: could not remove tag pointer(s) {failed_tags!r} from '
            f'{repo_full}. The repository has NOT been deleted. Please retry.',
        )
    # Step 2: remove every unique manifest blob.
    unique_digests = set(repo.tags.values_list('digest', flat=True))
    for digest in unique_digests:
        if not _registry_delete_manifest(repo_full, digest):
            logger.warning(
                'delete_repository: could not delete manifest %s from registry for %s — '
                'blob will be reclaimed by the next GC blob sweep',
                digest, repo_full,
            )
    log_action(request.auth, 'delete', 'repository', repo_name, {'name': repo_name}, project=project)
    repo.delete()
    return {'success': True, 'message': 'Repository deleted'}


# ── Tags ───────────────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/repositories/{repo_name}/tags', response=PaginatedTagsOut, auth=session_mfa_auth)
def list_tags(request, project_name: str, repo_name: str, limit: int = 20, offset: int = 0, search: str = ''):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    # Exclude per-platform child tags from the top-level list — they are shown
    # nested inside their parent index tag's detail page.
    qs = repo.tags.filter(parent_tag__isnull=True).select_related('pushed_by', 'signature_status').prefetch_related('scans', 'secret_scans', 'misconfig_scans', 'sbom_reports', 'labels', 'platform_children__scans', 'platform_children__secret_scans', 'platform_children__misconfig_scans', 'platform_children__sbom_reports')
    if search:
        qs = qs.filter(name__icontains=search)
    total = qs.count()
    items = list(qs[offset:offset + limit])
    return {'total': total, 'items': items}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}', response=TagDetailOut, auth=session_mfa_auth)
def get_tag(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    return get_object_or_404(
        Tag.objects.select_related('signature_status').prefetch_related(
            'scans', 'secret_scans', 'misconfig_scans', 'sbom_reports', 'labels',
            'platform_children__scans',
            'platform_children__secret_scans',
            'platform_children__misconfig_scans',
            'platform_children__sbom_reports',
        ),
        repository=repo, name=tag_name,
    )


@router.delete('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}', response=MessageOut, auth=session_mfa_auth)
def delete_tag(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_delete(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    repo_full = f'{project_name}/{repo_name}'
    digest = tag.digest
    # Always remove the tag name reference — this prevents catalog sync from
    # recreating the DB row. Removing a tag pointer never affects the manifest
    # blob; surviving sibling tags sharing the same digest remain reachable.
    # If the tag-pointer delete fails, abort so the registry and DB stay in sync.
    # A stale pointer left in Distribution would cause catalog sync to recreate
    # this tag row on its next run.
    if not _registry_delete_tag_ref(repo_full, tag_name):
        raise HttpError(
            502,
            f'Registry error: could not remove tag pointer for {repo_full}:{tag_name}. '
            f'The tag has NOT been deleted. Please retry.',
        )
    # Only remove the manifest blob when no sibling tag shares this digest.
    # Deleting a shared blob would make sibling tags 404 on the next orphan
    # check, cascade-deleting their scans and SBOMs.
    other_refs = Tag.objects.filter(repository=repo, digest=digest).exclude(pk=tag.pk).exists()
    if not other_refs:
        if not _registry_delete_manifest(repo_full, digest):
            logger.warning(
                'delete_tag: could not delete manifest %s from registry for %s:%s — '
                'blob will be reclaimed by the next GC blob sweep',
                digest, repo_full, tag_name,
            )
    log_action(request.auth, 'delete', 'tag', f'{repo_name}:{tag_name}',
               {'repository': repo_name, 'tag': tag_name, 'digest': digest}, project=project)
    tag.delete()
    return {'success': True, 'message': f'Tag {tag_name} deleted'}


@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/copy', response={201: MessageOut}, auth=session_mfa_auth)
def copy_tag(request, project_name: str, repo_name: str, tag_name: str, new_tag: str, dest_repo: str = ''):
    """
    Copy (retag) a tag by pushing its manifest under a new name.
    - new_tag:   required — the target tag name within the same (or destination) repository.
    - dest_repo: optional — destination repository name within the same project.
                 Defaults to the same repository as the source.

    Uses the registry's manifest API directly so no image data is transferred.
    """
    import requests as _req
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    src_tag = get_object_or_404(Tag, repository=repo, name=tag_name)

    if not new_tag or not new_tag.strip():
        raise HttpError(400, 'new_tag is required')

    dest_repo_name = dest_repo.strip() or repo_name
    dest_full = f'{project_name}/{dest_repo_name}'
    src_full  = f'{project_name}/{repo_name}'

    registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://localhost:5000')

    # Issue scoped JWTs — Docker Distribution only accepts RS256 tokens.
    from registry.auth import issue_token as _issue_token
    from django.contrib.auth.models import User as _User
    _admin = _User.objects.filter(is_superuser=True).first()
    _src_token = _issue_token(_admin, f'repository:{src_full}:pull')['token']
    _dst_token = _issue_token(_admin, f'repository:{dest_full}:push')['token']
    src_headers = {'Authorization': f'Bearer {_src_token}'}
    dst_headers = {'Authorization': f'Bearer {_dst_token}'}

    # Fetch the source manifest (use digest for exact match)
    manifest_url = f'{registry_base}/v2/{src_full}/manifests/{src_tag.digest}'
    resp = _req.get(manifest_url, headers={**src_headers, 'Accept': 'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,*/*'}, timeout=15)
    if not resp.ok:
        raise HttpError(502, f'Failed to fetch source manifest: {resp.status_code}')

    content_type = resp.headers.get('Content-Type', 'application/vnd.docker.distribution.manifest.v2+json')
    manifest_data = resp.content

    # Push manifest under new tag
    put_url = f'{registry_base}/v2/{dest_full}/manifests/{new_tag.strip()}'
    put_resp = _req.put(put_url, data=manifest_data,
                        headers={**dst_headers, 'Content-Type': content_type}, timeout=15)
    if not put_resp.ok:
        raise HttpError(502, f'Failed to push manifest: {put_resp.status_code}')

    log_action(request.auth, 'create', 'tag', f'{dest_repo_name}:{new_tag}',
               {'source': f'{repo_name}:{tag_name}', 'dest': f'{dest_repo_name}:{new_tag}'}, project=project)
    return 201, {'success': True, 'message': f'Copied to {dest_repo_name}:{new_tag}'}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/labels', response=list[LabelOut], auth=session_mfa_auth)
def get_tag_labels(request, project_name: str, repo_name: str, tag_name: str):
    """Return the labels currently attached to a tag."""
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    return list(tag.labels.all())


@router.put('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/labels', response=list[LabelOut], auth=session_mfa_auth)
def set_tag_labels(request, project_name: str, repo_name: str, tag_name: str, payload: TagLabelIn):
    """Replace the full set of labels on a tag. Pass an empty list to clear all labels.

    All provided label IDs must belong to the same project as the tag.
    """
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    # Validate every label belongs to this project
    labels = list(Label.objects.filter(id__in=payload.label_ids, project=project))
    if len(labels) != len(set(payload.label_ids)):
        raise HttpError(400, 'One or more label IDs are invalid or do not belong to this project')
    tag.labels.set(labels)
    log_action(request.auth, 'update', 'tag', f'{repo_name}:{tag_name}',
               {'labels': [lb.name for lb in labels]}, project=project)
    return labels


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/signature', response=SignatureStatusOut, auth=session_mfa_auth)
def get_signature_status(request, project_name: str, repo_name: str, tag_name: str):
    """Return the current signature verification status for a tag."""
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    sig, _ = TagSignatureStatus.objects.get_or_create(tag=tag)
    return sig


@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/signature/verify', response=MessageOut, auth=session_mfa_auth)
def trigger_signature_verify(request, project_name: str, repo_name: str, tag_name: str):
    """Queue an on-demand signature verification check for a tag."""
    from registry.tasks import run_signature_check
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    run_signature_check.apply_async(args=[tag.id], queue="default")
    log_action(request.auth, 'create', 'signature_check', f'{repo_name}:{tag_name}',
               {'repository': repo_name, 'tag': tag_name}, project=project)
    return {'success': True, 'message': 'Signature check queued'}


@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/scan', response=MessageOut, auth=session_mfa_auth)
def trigger_scan(request, project_name: str, repo_name: str, tag_name: str):
    from registry.tasks import run_vulnerability_scan
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    if tag.is_index:
        raise HttpError(400, 'Cannot scan a multi-arch index tag directly. Scans run per platform — use the platform child tag.')
    if _scan_already_inflight(VulnerabilityScan, tag):
        return {'success': True, 'message': 'Scan already in progress'}
    scan = VulnerabilityScan.objects.create(tag=tag)
    run_vulnerability_scan.apply_async(args=[scan.id], queue="scans")
    log_action(request.auth, 'create', 'scan', f'{repo_name}:{tag_name}',
               {'repository': repo_name, 'tag': tag_name}, project=project)
    return {'success': True, 'message': 'Scan queued'}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/scan/report', response=ScanReportOut, auth=session_mfa_auth)
def get_scan_report(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    scan = tag.scans.filter(status='finished').order_by('-finished_at').first() or tag.scans.order_by('-started_at').first()
    if not scan:
        raise HttpError(404, 'No scan found')
    # Annotate each finding with suppressed=True when it matches an allowlist entry
    suppressed_ids = _active_allowlist_ids(project, tag)
    if suppressed_ids and scan.report:
        annotated = []
        for finding in scan.report:
            vuln_id = (finding.get('vulnerability_id') or finding.get('VulnerabilityID') or finding.get('id') or '').lower()
            annotated.append({**finding, 'suppressed': vuln_id in suppressed_ids})
        summary = dict(scan.summary)
        summary['suppressed'] = sum(1 for f in annotated if f.get('suppressed'))
        # Subtract suppressed counts so the summary header reflects active CVEs only
        raw_crit = summary.get('critical', 0) or summary.get('CRITICAL', 0)
        raw_high = summary.get('high', 0) or summary.get('HIGH', 0)
        raw_med  = summary.get('medium', 0) or summary.get('MEDIUM', 0)
        raw_low  = summary.get('low', 0) or summary.get('LOW', 0)
        adj_crit, adj_high, adj_med, adj_low = _apply_allowlist_to_counts(
            annotated, suppressed_ids, raw_crit, raw_high, raw_med, raw_low
        )
        for k in ('critical', 'CRITICAL'):
            if k in summary:
                summary[k] = adj_crit
        for k in ('high', 'HIGH'):
            if k in summary:
                summary[k] = adj_high
        for k in ('medium', 'MEDIUM'):
            if k in summary:
                summary[k] = adj_med
        for k in ('low', 'LOW'):
            if k in summary:
                summary[k] = adj_low
        from types import SimpleNamespace
        proxy = SimpleNamespace(
            status=scan.status, summary=summary,
            started_at=scan.started_at, finished_at=scan.finished_at,
            report=annotated,
        )
        return proxy
    return scan


@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/sbom', response=MessageOut, auth=session_mfa_auth)
def trigger_sbom(request, project_name: str, repo_name: str, tag_name: str):
    from registry.tasks import run_sbom
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    if tag.is_index:
        raise HttpError(400, 'Cannot generate SBOM for a multi-arch index tag directly. SBOMs are generated per platform — use the platform child tag.')
    from registry.models import SBOMReport
    if _scan_already_inflight(SBOMReport, tag):
        return {'success': True, 'message': 'SBOM generation already in progress'}
    sbom = SBOMReport.objects.create(tag=tag)
    run_sbom.apply_async(args=[sbom.id], queue="sbom")
    log_action(request.auth, 'create', 'sbom', f'{repo_name}:{tag_name}',
               {'repository': repo_name, 'tag': tag_name}, project=project)
    return {'success': True, 'message': 'SBOM generation queued'}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/sbom', response=SBOMReportOut, auth=session_mfa_auth)
def get_sbom_report(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    sbom = tag.sbom_reports.filter(status='finished').order_by('-finished_at').first() or tag.sbom_reports.order_by('-created_at').first()
    if not sbom:
        raise HttpError(404, 'No SBOM found')
    return sbom


# ── Secret scanning ────────────────────────────────────────────────────────────

@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/secret-scan', response=MessageOut, auth=session_mfa_auth)
def trigger_secret_scan(request, project_name: str, repo_name: str, tag_name: str):
    from registry.tasks import run_secret_scan
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    if tag.is_index:
        raise HttpError(400, 'Cannot scan a multi-arch index tag directly. Scans run per platform — use the platform child tag.')
    if _scan_already_inflight(SecretScan, tag):
        return {'success': True, 'message': 'Secret scan already in progress'}
    scan = SecretScan.objects.create(tag=tag)
    run_secret_scan.apply_async(args=[scan.id], queue="scans")
    log_action(request.auth, 'create', 'secret_scan', f'{repo_name}:{tag_name}',
               {'repository': repo_name, 'tag': tag_name}, project=project)
    return {'success': True, 'message': 'Secret scan queued'}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/secret-scan/report', response=SecretScanReportOut, auth=session_mfa_auth)
def get_secret_scan_report(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    scan = tag.secret_scans.filter(status='finished').order_by('-finished_at').first() or tag.secret_scans.order_by('-started_at').first()
    if not scan:
        raise HttpError(404, 'No secret scan found')
    # Annotate each finding with suppressed=True and subtract from total
    suppressed_ids = _active_secret_allowlist_ids(tag)
    if suppressed_ids and scan.report:
        annotated = []
        suppressed_count = 0
        for finding in scan.report:
            rule_id = (finding.get('RuleID') or finding.get('rule_id') or '').lower()
            is_suppressed = rule_id in suppressed_ids
            annotated.append({**finding, 'suppressed': is_suppressed})
            if is_suppressed:
                suppressed_count += 1
        from types import SimpleNamespace
        proxy = SimpleNamespace(
            status=scan.status,
            total=max(0, (scan.total or 0) - suppressed_count),
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            report=annotated,
        )
        return proxy
    return scan


# ── Misconfiguration scanning ──────────────────────────────────────────────────

@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/misconfig-scan', response=MessageOut, auth=session_mfa_auth)
def trigger_misconfig_scan(request, project_name: str, repo_name: str, tag_name: str):
    from registry.tasks import run_misconfig_scan
    project = get_object_or_404(Project, name=project_name)
    require(can_push(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    if tag.is_index:
        raise HttpError(400, 'Cannot scan a multi-arch index tag directly. Scans run per platform — use the platform child tag.')
    if _scan_already_inflight(MisconfigScan, tag):
        return {'success': True, 'message': 'Misconfiguration scan already in progress'}
    scan = MisconfigScan.objects.create(tag=tag)
    run_misconfig_scan.apply_async(args=[scan.id], queue="scans")
    log_action(request.auth, 'create', 'misconfig_scan', f'{repo_name}:{tag_name}',
               {'repository': repo_name, 'tag': tag_name}, project=project)
    return {'success': True, 'message': 'Misconfiguration scan queued'}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/misconfig-scan/report', response=MisconfigScanReportOut, auth=session_mfa_auth)
def get_misconfig_scan_report(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    scan = tag.misconfig_scans.filter(status='finished').order_by('-finished_at').first() or tag.misconfig_scans.order_by('-started_at').first()
    if not scan:
        raise HttpError(404, 'No misconfiguration scan found')
    # Annotate each finding with suppressed=True and subtract from FAIL/WARN/PASS summary
    suppressed_ids = _active_misconfig_allowlist_ids(tag)
    if suppressed_ids and scan.report:
        annotated = []
        delta = {'FAIL': 0, 'WARN': 0, 'PASS': 0}
        for finding in scan.report:
            check_id = (finding.get('avd_id') or finding.get('id') or '').upper()
            is_suppressed = check_id.lower() in suppressed_ids
            annotated.append({**finding, 'suppressed': is_suppressed})
            if is_suppressed:
                status = (finding.get('status') or finding.get('Status') or '').upper()
                if status in delta:
                    delta[status] += 1
        summary = dict(scan.summary or {})
        for k in ('FAIL', 'WARN', 'PASS'):
            summary[k] = max(0, summary.get(k, 0) - delta[k])
        from types import SimpleNamespace
        proxy = SimpleNamespace(
            status=scan.status,
            summary=summary,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            report=annotated,
        )
        return proxy
    return scan


# ── Project Audit Logs ────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/audit-logs', response=list[AuditLogOut], auth=session_mfa_auth)
def project_audit_logs(
    request, project_name: str,
    limit: int = 200, offset: int = 0,
    operation: str = '',
    date_from: str = '',
    date_to: str = '',
    q: str = '',
):
    """Audit log entries scoped to a single project. Supports server-side filtering."""
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz

    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    qs = AuditLog.objects.filter(project=project).select_related('user', 'project')
    if operation:
        qs = qs.filter(operation=operation)
    if date_from:
        dt = parse_datetime(date_from + 'T00:00:00') or None
        if dt:
            qs = qs.filter(timestamp__gte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if date_to:
        dt = parse_datetime(date_to + 'T23:59:59') or None
        if dt:
            qs = qs.filter(timestamp__lte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if q:
        qs = qs.filter(
            models.Q(username__icontains=q) | models.Q(resource__icontains=q)
        )
    return qs.order_by('-timestamp')[offset:offset + limit]


@router.get('/projects/{project_name}/audit-logs/export', auth=session_mfa_auth)
def export_project_audit_logs(
    request, project_name: str,
    format: str = 'csv',
    operation: str = '',
    date_from: str = '',
    date_to: str = '',
    q: str = '',
):
    """Export all matching audit log entries as CSV or JSON (no pagination)."""
    from django.http import HttpResponse
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz
    import csv, io, json as _json

    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    qs = AuditLog.objects.filter(project=project).select_related('project')
    if operation:
        qs = qs.filter(operation=operation)
    if date_from:
        dt = parse_datetime(date_from + 'T00:00:00') or None
        if dt:
            qs = qs.filter(timestamp__gte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if date_to:
        dt = parse_datetime(date_to + 'T23:59:59') or None
        if dt:
            qs = qs.filter(timestamp__lte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if q:
        qs = qs.filter(models.Q(username__icontains=q) | models.Q(resource__icontains=q))
    entries = list(qs.order_by('-timestamp').values(
        'id', 'username', 'operation', 'resource_type', 'resource',
        'result', 'detail', 'timestamp',
    ))

    fmt = (format or 'csv').lower()
    filename_base = f'audit-log-{project_name}'

    if fmt == 'json':
        for e in entries:
            e['timestamp'] = e['timestamp'].isoformat()
        response = HttpResponse(
            _json.dumps(entries, indent=2),
            content_type='application/json',
        )
        response['Content-Disposition'] = f'attachment; filename="{filename_base}.json"'
        return response

    # CSV (default)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['id', 'timestamp', 'username', 'operation', 'resource_type', 'resource', 'result', 'detail'])
    for e in entries:
        writer.writerow([
            e['id'],
            e['timestamp'].isoformat(),
            e['username'],
            e['operation'],
            e['resource_type'],
            e['resource'],
            e['result'],
            _json.dumps(e['detail']) if e['detail'] else '',
        ])
    response = HttpResponse(buf.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename_base}.csv"'
    return response


@router.get('/projects/{project_name}/activity', auth=session_mfa_auth)
def project_activity(request, project_name: str, days: int = 365):
    """Daily push/pull counts for a project over the last N days."""
    from django.utils import timezone
    from django.db.models.functions import TruncDate
    from django.db.models import Count, Q

    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    since = timezone.now() - timezone.timedelta(days=days)
    rows = (
        AuditLog.objects
        .filter(project=project, timestamp__gte=since, operation__in=['push', 'pull'])
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(
            pushes=Count('id', filter=Q(operation='push')),
            pulls=Count('id', filter=Q(operation='pull')),
        )
        .order_by('date')
    )
    return [
        {'date': str(r['date']), 'pushes': r['pushes'], 'pulls': r['pulls']}
        for r in rows
    ]


# ── Project Security Hub ───────────────────────────────────────────────────────

@router.get('/projects/{project_name}/security', response=list[VulnSummaryOut], auth=session_mfa_auth)
def project_security_hub(request, project_name: str, severity: str = ''):
    """Vulnerability summary for all tags in a single project."""
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))

    scans = VulnerabilityScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(
        status='finished',
        tag__repository__project=project,
    ).order_by('-finished_at')

    # Pre-fetch all active allowlist entries for this project once (avoids N+1)
    from django.utils import timezone as _tz
    _now = _tz.now()
    allowlist_qs = VulnAllowlistEntry.objects.filter(project=project).filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('cve_id', 'tag_id')
    # project-wide ids (tag_id is None)
    project_wide_ids = {e['cve_id'].lower() for e in allowlist_qs if e['tag_id'] is None}
    # tag-specific ids grouped by tag pk
    tag_specific: dict[int, set[str]] = {}
    for e in allowlist_qs:
        if e['tag_id'] is not None:
            tag_specific.setdefault(e['tag_id'], set()).add(e['cve_id'].lower())

    results = []
    seen_tags: set[int] = set()

    for scan in scans:
        tag = scan.tag
        if tag.id in seen_tags:
            continue
        seen_tags.add(tag.id)

        summary = scan.summary or {}
        crit = summary.get('critical', 0) or summary.get('CRITICAL', 0)
        high = summary.get('high', 0) or summary.get('HIGH', 0)
        med  = summary.get('medium', 0) or summary.get('MEDIUM', 0)
        low  = summary.get('low', 0) or summary.get('LOW', 0)

        # Subtract allowlisted CVEs from counts
        suppressed_ids = project_wide_ids | tag_specific.get(tag.id, set())
        if suppressed_ids and scan.report:
            crit, high, med, low = _apply_allowlist_to_counts(
                scan.report, suppressed_ids, crit, high, med, low
            )

        if severity == 'critical' and crit == 0:
            continue
        if severity == 'high' and crit + high == 0:
            continue

        results.append({
            'tag_id': tag.id,
            'tag_name': tag.name,
            'repository': tag.repository.name,
            'project': project_name,
            'scan_status': scan.status,
            'critical': crit,
            'high': high,
            'medium': med,
            'low': low,
            'scanned_at': scan.finished_at,
        })

    return results


# ---------------------------------------------------------------------------
# Worker queue health — self-heal stale scan/SBOM rows + orphaned queue
# ---------------------------------------------------------------------------

@router.post('/system/workers/reset-stale', response=MessageOut, auth=admin_session_auth)
def reset_stale_workers(request):
    """
    Resets any scan/SBOM rows stuck in 'pending' or 'running' back to 'error'
    so they can be re-triggered, and flushes the orphaned default 'celery' queue
    in Redis (messages left over from before the apply_async queue routing fix).
    """
    import redis as redis_lib

    stuck_statuses = (VulnerabilityScan.STATUS_PENDING, VulnerabilityScan.STATUS_RUNNING)

    vuln_n    = VulnerabilityScan.objects.filter(status__in=stuck_statuses).update(status='error')
    secret_n  = SecretScan.objects.filter(status__in=stuck_statuses).update(status='error')
    misconf_n = MisconfigScan.objects.filter(status__in=stuck_statuses).update(status='error')
    sbom_n    = SBOMReport.objects.filter(status__in=('pending', 'running')).update(status='error')

    # Flush orphaned messages sitting in the bare 'celery' default queue
    flushed = 0
    try:
        broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
        r = redis_lib.from_url(broker_url)
        flushed = r.llen('celery')
        if flushed:
            r.delete('celery')
    except Exception:
        pass  # Non-fatal — DB reset is the important part

    total = vuln_n + secret_n + misconf_n + sbom_n
    log_action(request.auth, 'update', 'workers', 'reset-stale', {
        'vuln': vuln_n, 'secret': secret_n, 'misconfig': misconf_n,
        'sbom': sbom_n, 'queue_flushed': flushed,
    })
    return {
        'success': True,
        'message': (
            f'Reset {total} stuck job(s) to error '
            f'(vuln={vuln_n}, secret={secret_n}, misconfig={misconf_n}, sbom={sbom_n})'
            + (f'; flushed {flushed} orphaned message(s) from celery queue' if flushed else '')
        ),
    }

@router.get('/projects/{project_name}/security/secrets', response=list[SecretSummaryOut], auth=session_mfa_auth)
def project_secret_security_hub(request, project_name: str):
    """Secret scan summary for all tags in a single project."""
    from registry.models import SecretScan
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))

    scans = SecretScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished', tag__repository__project=project).order_by('-finished_at')

    # Pre-fetch all active secret allowlist entries for this project (avoids N+1)
    # Includes project-wide (tag=None) and tag-specific entries.
    from django.utils import timezone as _tz
    _now = _tz.now()
    sal_qs = SecretAllowlistEntry.objects.filter(
        models.Q(project=project, tag__isnull=True) | models.Q(tag__repository__project=project)
    ).filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('tag_id', 'rule_id')
    project_wide_secret_ids: set[str] = set()
    secret_tag_suppressed: dict[int, set[str]] = {}
    for e in sal_qs:
        if e['tag_id'] is None:
            project_wide_secret_ids.add(e['rule_id'].lower())
        else:
            secret_tag_suppressed.setdefault(e['tag_id'], set()).add(e['rule_id'].lower())

    results = []
    seen: set[int] = set()
    for scan in scans:
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        total = scan.total or 0
        suppressed_ids = project_wide_secret_ids | secret_tag_suppressed.get(scan.tag_id, set())
        if suppressed_ids and scan.report:
            for finding in scan.report:
                rule_id = (finding.get('RuleID') or finding.get('rule_id') or '').lower()
                if rule_id in suppressed_ids:
                    total = max(0, total - 1)
        results.append({
            'tag_id': scan.tag_id,
            'tag_name': scan.tag.name,
            'repository': scan.tag.repository.name,
            'project': project_name,
            'scan_status': scan.status,
            'total': total,
            'scanned_at': scan.finished_at,
        })
    return results


@router.get('/projects/{project_name}/security/misconfigs', response=list[MisconfigSummaryOut], auth=session_mfa_auth)
def project_misconfig_security_hub(request, project_name: str):
    """Misconfiguration scan summary for all tags in a single project."""
    from registry.models import MisconfigScan
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))

    scans = MisconfigScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished', tag__repository__project=project).order_by('-finished_at')

    # Pre-fetch all active misconfig allowlist entries for this project (avoids N+1)
    # Includes project-wide (tag=None) and tag-specific entries.
    from django.utils import timezone as _tz
    _now = _tz.now()
    mal_qs = MisconfigAllowlistEntry.objects.filter(
        models.Q(project=project, tag__isnull=True) | models.Q(tag__repository__project=project)
    ).filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('tag_id', 'check_id')
    project_wide_misconfig_ids: set[str] = set()
    misconfig_tag_suppressed: dict[int, set[str]] = {}
    for e in mal_qs:
        if e['tag_id'] is None:
            project_wide_misconfig_ids.add(e['check_id'].lower())
        else:
            misconfig_tag_suppressed.setdefault(e['tag_id'], set()).add(e['check_id'].lower())

    results = []
    seen: set[int] = set()
    for scan in scans:
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        s = scan.summary or {}
        fail = s.get('FAIL', 0)
        warn = s.get('WARN', 0)
        pass_c = s.get('PASS', 0)
        suppressed_ids = project_wide_misconfig_ids | misconfig_tag_suppressed.get(scan.tag_id, set())
        if suppressed_ids and scan.report:
            for finding in scan.report:
                check_id = (finding.get('avd_id') or finding.get('id') or '').upper()
                if check_id.lower() in suppressed_ids:
                    status = (finding.get('status') or finding.get('Status') or '').upper()
                    if status == 'FAIL':
                        fail = max(0, fail - 1)
                    elif status == 'WARN':
                        warn = max(0, warn - 1)
                    elif status == 'PASS':
                        pass_c = max(0, pass_c - 1)
        results.append({
            'tag_id': scan.tag_id,
            'tag_name': scan.tag.name,
            'repository': scan.tag.repository.name,
            'project': project_name,
            'scan_status': scan.status,
            'fail': fail,
            'warn': warn,
            'pass_count': pass_c,
            'scanned_at': scan.finished_at,
        })
    return results


@router.get('/system/security/secrets', response=list[SecretSummaryOut], auth=admin_session_auth)
def system_secret_security_hub(request, project: str = '', projects: str = ''):
    """System-wide secret scan summary."""
    from registry.models import SecretScan
    scans = SecretScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished').order_by('-finished_at')
    # `projects` (comma-separated) takes precedence over legacy single `project`
    project_list = [p.strip() for p in projects.split(',') if p.strip()] if projects else ([project] if project else [])
    if project_list:
        scans = scans.filter(tag__repository__project__name__in=project_list)

    # Pre-fetch all active secret allowlist entries in scope
    from django.utils import timezone as _tz
    _now = _tz.now()
    sal_qs = SecretAllowlistEntry.objects.filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('tag_id', 'project_id', 'rule_id')
    if project_list:
        sal_qs = sal_qs.filter(
            models.Q(tag__repository__project__name__in=project_list) | models.Q(project__name__in=project_list, tag__isnull=True)
        )
    # project-wide ids keyed by project_id; tag-specific keyed by tag_id
    secret_project_suppressed: dict[int, set[str]] = {}
    secret_tag_suppressed: dict[int, set[str]] = {}
    for e in sal_qs:
        if e['tag_id'] is None and e['project_id'] is not None:
            secret_project_suppressed.setdefault(e['project_id'], set()).add(e['rule_id'].lower())
        elif e['tag_id'] is not None:
            secret_tag_suppressed.setdefault(e['tag_id'], set()).add(e['rule_id'].lower())

    results = []
    seen: set[int] = set()
    for scan in scans:
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        total = scan.total or 0
        proj_id = scan.tag.repository.project_id
        suppressed_ids = secret_project_suppressed.get(proj_id, set()) | secret_tag_suppressed.get(scan.tag_id, set())
        if suppressed_ids and scan.report:
            for finding in scan.report:
                rule_id = (finding.get('RuleID') or finding.get('rule_id') or '').lower()
                if rule_id in suppressed_ids:
                    total = max(0, total - 1)
        results.append({
            'tag_id': scan.tag_id,
            'tag_name': scan.tag.name,
            'repository': scan.tag.repository.name,
            'project': scan.tag.repository.project.name,
            'scan_status': scan.status,
            'total': total,
            'scanned_at': scan.finished_at,
        })
    return results


@router.get('/system/security/misconfigs', response=list[MisconfigSummaryOut], auth=admin_session_auth)
def system_misconfig_security_hub(request, project: str = '', projects: str = ''):
    """System-wide misconfiguration scan summary."""
    from registry.models import MisconfigScan
    scans = MisconfigScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished').order_by('-finished_at')
    # `projects` (comma-separated) takes precedence over legacy single `project`
    project_list = [p.strip() for p in projects.split(',') if p.strip()] if projects else ([project] if project else [])
    if project_list:
        scans = scans.filter(tag__repository__project__name__in=project_list)

    # Pre-fetch all active misconfig allowlist entries in scope
    from django.utils import timezone as _tz
    _now = _tz.now()
    mal_qs = MisconfigAllowlistEntry.objects.filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('tag_id', 'project_id', 'check_id')
    if project_list:
        mal_qs = mal_qs.filter(
            models.Q(tag__repository__project__name__in=project_list) | models.Q(project__name__in=project_list, tag__isnull=True)
        )
    misconfig_project_suppressed: dict[int, set[str]] = {}
    misconfig_tag_suppressed: dict[int, set[str]] = {}
    for e in mal_qs:
        if e['tag_id'] is None and e['project_id'] is not None:
            misconfig_project_suppressed.setdefault(e['project_id'], set()).add(e['check_id'].lower())
        elif e['tag_id'] is not None:
            misconfig_tag_suppressed.setdefault(e['tag_id'], set()).add(e['check_id'].lower())

    results = []
    seen: set[int] = set()
    for scan in scans:
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        s = scan.summary or {}
        fail = s.get('FAIL', 0)
        warn = s.get('WARN', 0)
        pass_c = s.get('PASS', 0)
        proj_id = scan.tag.repository.project_id
        suppressed_ids = misconfig_project_suppressed.get(proj_id, set()) | misconfig_tag_suppressed.get(scan.tag_id, set())
        if suppressed_ids and scan.report:
            for finding in scan.report:
                check_id = (finding.get('avd_id') or finding.get('id') or '').upper()
                if check_id.lower() in suppressed_ids:
                    status = (finding.get('status') or finding.get('Status') or '').upper()
                    if status == 'FAIL':
                        fail = max(0, fail - 1)
                    elif status == 'WARN':
                        warn = max(0, warn - 1)
                    elif status == 'PASS':
                        pass_c = max(0, pass_c - 1)
        results.append({
            'tag_id': scan.tag_id,
            'tag_name': scan.tag.name,
            'repository': scan.tag.repository.name,
            'project': scan.tag.repository.project.name,
            'scan_status': scan.status,
            'fail': fail,
            'warn': warn,
            'pass_count': pass_c,
            'scanned_at': scan.finished_at,
        })
    return results


# ── Insight / Aggregation endpoints ───────────────────────────────────────────

@router.get('/system/insights/storage-by-project', auth=admin_session_auth)
def system_storage_by_project(request):
    """Storage consumed per project, sorted largest first."""
    from django.db.models import Sum, Count
    rows = (
        Tag.objects
        .values('repository__project__name')
        .annotate(storage_bytes=Sum('size_bytes'), tag_count=Count('id'))
        .order_by('-storage_bytes')
    )
    return [
        {
            'project': r['repository__project__name'],
            'storage_bytes': r['storage_bytes'] or 0,
            'tag_count': r['tag_count'],
        }
        for r in rows
    ]


@router.get('/system/insights/top-repos', auth=admin_session_auth)
def system_top_repos(request, limit: int = 10, order_by: str = 'pulls', projects: str = ''):
    """Top repositories by pull or push count."""
    field = 'pull_count' if order_by != 'pushes' else 'push_count'
    qs = Repository.objects.select_related('project')
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(project__name__in=project_list)
    repos = qs.order_by(f'-{field}')[:limit]
    return [
        {
            'name': r.name,
            'project': r.project.name,
            'full_name': r.full_name,
            'pull_count': r.pull_count,
            'push_count': r.push_count,
            'tag_count': r.tags.count(),
        }
        for r in repos
    ]


@router.get('/system/insights/operation-mix', auth=admin_session_auth)
def system_operation_mix(request, days: int = 30, projects: str = ''):
    """Audit log operation breakdown (counts per operation type) for the last N days."""
    from django.utils import timezone
    from django.db.models import Count
    since = timezone.now() - timezone.timedelta(days=days)
    qs = AuditLog.objects.filter(timestamp__gte=since)
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(project__name__in=project_list)
    rows = (
        qs
        .values('operation')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    return [{'operation': r['operation'], 'count': r['count']} for r in rows]


@router.get('/system/insights/image-platforms', auth=admin_session_auth)
def system_image_platforms(request, projects: str = ''):
    """Distribution of tag OS × architecture combinations."""
    from django.db.models import Count
    qs = Tag.objects
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(repository__project__name__in=project_list)
    rows = (
        qs
        .values('os', 'architecture')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    return [
        {
            'os': r['os'] or 'unknown',
            'architecture': r['architecture'] or 'unknown',
            'count': r['count'],
            'label': f"{r['os'] or 'unknown'}/{r['architecture'] or 'unknown'}",
        }
        for r in rows
    ]


@router.get('/system/insights/scan-coverage', auth=admin_session_auth)
def system_scan_coverage(request, projects: str = ''):
    """How many tags have a completed scan vs. total tags, broken down by project."""
    from django.db.models import Count, Q
    qs = Tag.objects
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(repository__project__name__in=project_list)
    rows = (
        qs
        .values('repository__project__name')
        .annotate(
            total=Count('id', distinct=True),
            scanned=Count('id', distinct=True, filter=Q(scans__status='finished')),
        )
        .order_by('repository__project__name')
    )
    system_total = qs.count()
    system_scanned = qs.filter(scans__status='finished').distinct().count()
    return {
        'total': system_total,
        'scanned': system_scanned,
        'by_project': [
            {
                'project': r['repository__project__name'],
                'total': r['total'],
                'scanned': r['scanned'],
            }
            for r in rows
        ],
    }


@router.get('/system/insights/vuln-by-project', auth=admin_session_auth)
def system_vuln_by_project(request, projects: str = ''):
    """Sum of critical/high/medium/low CVEs per project (latest scan per tag)."""
    qs = VulnerabilityScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished')
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(tag__repository__project__name__in=project_list)
    scans = qs.order_by('-finished_at')

    # Pre-fetch all active allowlist entries across the registry (avoids N+1)
    from django.utils import timezone as _tz
    _now = _tz.now()
    al_qs = VulnAllowlistEntry.objects.filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('cve_id', 'tag_id', 'project_id')
    proj_wide: dict[int, set[str]] = {}
    tag_spec: dict[int, set[str]] = {}
    for e in al_qs:
        if e['tag_id'] is None:
            proj_wide.setdefault(e['project_id'], set()).add(e['cve_id'].lower())
        else:
            tag_spec.setdefault(e['tag_id'], set()).add(e['cve_id'].lower())

    # deduplicate: keep only the latest scan per tag
    seen_tags: set[int] = set()
    by_project: dict[str, dict] = {}
    for scan in scans:
        tag = scan.tag
        if tag.id in seen_tags:
            continue
        seen_tags.add(tag.id)
        proj = tag.repository.project.name
        proj_id = tag.repository.project_id
        summary = scan.summary or {}
        crit = summary.get('critical', 0) or summary.get('CRITICAL', 0)
        high = summary.get('high', 0) or summary.get('HIGH', 0)
        med  = summary.get('medium', 0) or summary.get('MEDIUM', 0)
        low  = summary.get('low', 0) or summary.get('LOW', 0)

        # Subtract allowlisted CVEs from counts
        suppressed_ids = proj_wide.get(proj_id, set()) | tag_spec.get(tag.id, set())
        if suppressed_ids and scan.report:
            crit, high, med, low = _apply_allowlist_to_counts(
                scan.report, suppressed_ids, crit, high, med, low
            )

        if proj not in by_project:
            by_project[proj] = {'project': proj, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'image_count': 0}
        by_project[proj]['critical']    += crit
        by_project[proj]['high']        += high
        by_project[proj]['medium']      += med
        by_project[proj]['low']         += low
        by_project[proj]['image_count'] += 1

    return sorted(by_project.values(), key=lambda r: r['critical'] + r['high'], reverse=True)


@router.get('/system/insights/image-stats', auth=admin_session_auth)
def system_image_stats(request, projects: str = ''):
    """Average, median and total image (tag) size across the registry."""
    from django.db.models import Avg, Max, Min, Count
    qs = Tag.objects
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(repository__project__name__in=project_list)
    agg = qs.aggregate(
        avg_bytes=Avg('size_bytes'),
        max_bytes=Max('size_bytes'),
        min_bytes=Min('size_bytes'),
        total_bytes=Sum('size_bytes'),
        total_tags=Count('id'),
    )
    return {
        'avg_bytes':   int(agg['avg_bytes'] or 0),
        'max_bytes':   agg['max_bytes'] or 0,
        'min_bytes':   agg['min_bytes'] or 0,
        'total_bytes': agg['total_bytes'] or 0,
        'total_tags':  agg['total_tags'] or 0,
    }


# ── Project-scoped insight endpoints ─────────────────────────────────────────

@router.get('/projects/{project_name}/insights/top-repos', auth=session_mfa_auth)
def project_top_repos(request, project_name: str, limit: int = 10):
    """Top repositories in this project by push count."""
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repos = (
        Repository.objects
        .filter(project=project)
        .order_by('-push_count')[:limit]
    )
    return [
        {
            'name': r.name,
            'project': project_name,
            'full_name': r.full_name,
            'pull_count': r.pull_count,
            'push_count': r.push_count,
            'tag_count': r.tags.count(),
        }
        for r in repos
    ]


@router.get('/projects/{project_name}/insights/operation-mix', auth=session_mfa_auth)
def project_operation_mix(request, project_name: str, days: int = 30):
    """Audit log operation breakdown for this project over the last N days."""
    from django.utils import timezone
    from django.db.models import Count
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    since = timezone.now() - timezone.timedelta(days=days)
    rows = (
        AuditLog.objects
        .filter(project=project, timestamp__gte=since)
        .values('operation')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    return [{'operation': r['operation'], 'count': r['count']} for r in rows]


@router.get('/projects/{project_name}/insights/image-platforms', auth=session_mfa_auth)
def project_image_platforms(request, project_name: str):
    """OS × architecture distribution of tags in this project."""
    from django.db.models import Count
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    rows = (
        Tag.objects
        .filter(repository__project=project)
        .values('os', 'architecture')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    return [
        {
            'os': r['os'] or 'unknown',
            'architecture': r['architecture'] or 'unknown',
            'count': r['count'],
            'label': f"{r['os'] or 'unknown'}/{r['architecture'] or 'unknown'}",
        }
        for r in rows
    ]


@router.get('/projects/{project_name}/insights/scan-coverage', auth=session_mfa_auth)
def project_scan_coverage(request, project_name: str):
    """Scanned vs. total tags for this project."""
    from django.db.models import Exists, OuterRef
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    tags = Tag.objects.filter(repository__project=project)
    total = tags.count()
    finished_scan = VulnerabilityScan.objects.filter(tag=OuterRef('pk'), status='finished')
    scanned = tags.filter(Exists(finished_scan)).count()
    return {
        'total':   total,
        'scanned': scanned,
    }


@router.get('/projects/{project_name}/insights/image-stats', auth=session_mfa_auth)
def project_image_stats(request, project_name: str):
    """Average, max, min tag size for this project."""
    from django.db.models import Avg, Max, Min, Count
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    agg = Tag.objects.filter(repository__project=project).aggregate(
        avg_bytes=Avg('size_bytes'),
        max_bytes=Max('size_bytes'),
        min_bytes=Min('size_bytes'),
        total_bytes=Sum('size_bytes'),
        total_tags=Count('id'),
    )
    return {
        'avg_bytes':   int(agg['avg_bytes'] or 0),
        'max_bytes':   agg['max_bytes'] or 0,
        'min_bytes':   agg['min_bytes'] or 0,
        'total_bytes': agg['total_bytes'] or 0,
        'total_tags':  agg['total_tags'] or 0,
    }


@router.get('/projects/{project_name}/insights/member-roles', auth=session_mfa_auth)
def project_member_roles(request, project_name: str):
    """Member role distribution for this project."""
    from django.db.models import Count
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    rows = (
        ProjectMember.objects
        .filter(project=project)
        .values('role')
        .annotate(count=Count('id'))
        .order_by('role')
    )
    return [{'role': r['role'], 'count': r['count']} for r in rows]


# ── Robot Accounts ─────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/robots', response=list[RobotOut], auth=session_mfa_auth)
def list_robots(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    return project.robot_accounts.all()


@router.post('/projects/{project_name}/robots', response={201: RobotCreatedOut}, auth=session_mfa_auth)
def create_robot(request, project_name: str, payload: RobotIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    if RobotAccount.objects.filter(name__iexact=payload.name).exists():
        raise HttpError(409, 'A robot account with that name already exists')
    if User.objects.filter(username__iexact=payload.name).exists():
        raise HttpError(409, 'A user with that username already exists')
    secret = secrets.token_urlsafe(32)
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    robot = RobotAccount.objects.create(
        project=project,
        name=payload.name,
        description=payload.description,
        secret_hash=secret_hash,
        permissions=payload.permissions,
        expires_at=payload.expires_at,
        created_by=request.auth,
    )
    log_action(request.auth, 'create', 'robot', payload.name,
               {'name': payload.name, 'description': payload.description,
                'expires_at': payload.expires_at.isoformat() if payload.expires_at else None},
               project=project)
    return 201, {
        'id': robot.id,
        'name': robot.name,
        'description': robot.description,
        'permissions': robot.permissions,
        'expires_at': robot.expires_at,
        'disabled': robot.disabled,
        'created_at': robot.created_at,
        'secret': secret,
    }


@router.patch('/projects/{project_name}/robots/{robot_id}', response=RobotOut, auth=session_mfa_auth)
def update_robot(request, project_name: str, robot_id: int, payload: RobotPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    robot = get_object_or_404(RobotAccount, id=robot_id, project=project)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return robot
    if 'name' in changes and changes['name'].lower() != robot.name.lower():
        if RobotAccount.objects.filter(name__iexact=changes['name']).exclude(id=robot_id).exists():
            raise HttpError(409, 'A robot account with that name already exists')
        if User.objects.filter(username__iexact=changes['name']).exists():
            raise HttpError(409, 'A user with that username already exists')
    for field, value in changes.items():
        setattr(robot, field, value)
    robot.save()
    log_action(request.auth, 'update', 'robot', robot.name, {'changes': changes}, project=project)
    return robot


@router.post('/projects/{project_name}/robots/{robot_id}/rotate', response=dict, auth=session_mfa_auth)
def rotate_robot_secret(request, project_name: str, robot_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    robot = get_object_or_404(RobotAccount, id=robot_id, project=project)
    secret = secrets.token_urlsafe(32)
    robot.secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    robot.save(update_fields=['secret_hash'])
    log_action(request.auth, 'update', 'robot', robot.name, {'action': 'rotate_secret'}, project=project)
    return {'secret': secret}


@router.delete('/projects/{project_name}/robots/{robot_id}', response=MessageOut, auth=session_mfa_auth)
def delete_robot(request, project_name: str, robot_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_members(request.auth, project))
    robot = get_object_or_404(RobotAccount, id=robot_id, project=project)
    log_action(request.auth, 'delete', 'robot', robot.name, {'name': robot.name}, project=project)
    robot.delete()
    return {'success': True, 'message': 'Robot account deleted'}


# ── User Search ───────────────────────────────────────────────────────────────

@router.get('/users/search', response=list[UserSearchOut], auth=session_mfa_auth)
def search_users(request, q: str = '', project_name: str = '', limit: int = 10):
    """
    Returns up to `limit` users whose username or email contains `q`.
    If `project_name` is given, users already in that project are excluded.
    """
    qs = User.objects.all()
    if q:
        qs = qs.filter(username__icontains=q) | User.objects.filter(email__icontains=q)
    if project_name:
        existing_ids = ProjectMember.objects.filter(
            project__name=project_name
        ).values_list('user_id', flat=True)
        qs = qs.exclude(id__in=existing_ids)
    return list(qs.order_by('username')[:limit])


# ── System (Admin only) ────────────────────────────────────────────────────────

@router.get('/system/users', response=list[dict], auth=admin_session_auth)
def list_users(request):
    users = User.objects.select_related('userprofile').all()
    return [
        {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'is_admin': getattr(u, 'userprofile', None) and u.userprofile.is_admin,
            'date_joined': u.date_joined.isoformat(),
            'last_login': u.last_login.isoformat() if u.last_login else None,
        }
        for u in users
    ]


@router.get('/system/users/check-availability', auth=admin_session_auth)
def check_user_availability(request, username: str = '', email: str = ''):
    """Check whether a username and/or email are available (not taken by any user or robot)."""
    result = {}
    if username:
        taken = (
            User.objects.filter(username__iexact=username).exists() or
            RobotAccount.objects.filter(name__iexact=username).exists()
        )
        result['username_available'] = not taken
    if email:
        result['email_available'] = not User.objects.filter(email__iexact=email).exists()
    return result


@router.post('/system/users', response={201: dict}, auth=admin_session_auth)
def create_user(request, payload: CreateUserIn):
    from users.models import UserProfile
    if User.objects.filter(username__iexact=payload.username).exists():
        raise HttpError(409, 'A user with that username already exists')
    if RobotAccount.objects.filter(name__iexact=payload.username).exists():
        raise HttpError(409, 'A robot account with that name already exists')
    if User.objects.filter(email__iexact=payload.email).exists():
        raise HttpError(409, 'A user with that email already exists')
    if len(payload.password) < 8:
        raise HttpError(400, 'Password must be at least 8 characters')
    user = User.objects.create_user(
        username=payload.username,
        email=payload.email,
        password=payload.password,
    )
    UserProfile.objects.get_or_create(user=user)
    log_action(request.auth, 'create', 'user', user.username,
               {'username': user.username, 'email': user.email})
    return 201, {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': False,
        'date_joined': user.date_joined.isoformat(),
        'last_login': None,
    }


@router.patch('/system/users/{user_id}', response=dict, auth=admin_session_auth)
def patch_user(request, user_id: int, payload: PatchUserIn):
    from users.models import UserProfile
    user = get_object_or_404(User, id=user_id)
    if user == request.auth:
        raise HttpError(400, 'Cannot change your own admin status')
    profile, _ = UserProfile.objects.get_or_create(user=user)
    if profile.is_admin == payload.is_admin:
        # no-op
        pass
    else:
        profile.is_admin = payload.is_admin
        profile.save(update_fields=['is_admin'])
        action = 'promote' if payload.is_admin else 'demote'
        log_action(request.auth, 'update', 'user', user.username,
                   {'action': action, 'is_admin': payload.is_admin})
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': profile.is_admin,
        'date_joined': user.date_joined.isoformat(),
        'last_login': user.last_login.isoformat() if user.last_login else None,
    }


@router.delete('/system/users/{user_id}', response=MessageOut, auth=admin_session_auth)
def delete_user(request, user_id: int):
    user = get_object_or_404(User, id=user_id)
    if user == request.auth:
        raise HttpError(400, 'Cannot delete yourself')
    log_action(request.auth, 'delete', 'user', user.username,
               {'username': user.username, 'email': user.email})
    user.delete()
    return {'success': True, 'message': f'User {user.username} deleted'}


@router.get('/system/audit-logs', response=list[AuditLogOut], auth=admin_session_auth)
def system_audit_logs(
    request,
    limit: int = 200, offset: int = 0,
    operation: str = '',
    project_name: str = '',
    date_from: str = '',
    date_to: str = '',
    q: str = '',
):
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz

    qs = AuditLog.objects.select_related('user', 'project').all()
    if operation:
        qs = qs.filter(operation=operation)
    if project_name:
        qs = qs.filter(project__name=project_name)
    if date_from:
        dt = parse_datetime(date_from + 'T00:00:00') or None
        if dt:
            qs = qs.filter(timestamp__gte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if date_to:
        dt = parse_datetime(date_to + 'T23:59:59') or None
        if dt:
            qs = qs.filter(timestamp__lte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if q:
        qs = qs.filter(
            models.Q(username__icontains=q) | models.Q(resource__icontains=q)
        )
    return qs.order_by('-timestamp')[offset:offset + limit]


@router.get('/system/audit-logs/export', auth=admin_session_auth)
def export_system_audit_logs(
    request,
    format: str = 'csv',
    operation: str = '',
    project_name: str = '',
    date_from: str = '',
    date_to: str = '',
    q: str = '',
):
    """Export all matching system-wide audit log entries as CSV or JSON (no pagination)."""
    from django.http import HttpResponse
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz
    import csv, io, json as _json

    qs = AuditLog.objects.select_related('project').all()
    if operation:
        qs = qs.filter(operation=operation)
    if project_name:
        qs = qs.filter(project__name=project_name)
    if date_from:
        dt = parse_datetime(date_from + 'T00:00:00') or None
        if dt:
            qs = qs.filter(timestamp__gte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if date_to:
        dt = parse_datetime(date_to + 'T23:59:59') or None
        if dt:
            qs = qs.filter(timestamp__lte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if q:
        qs = qs.filter(models.Q(username__icontains=q) | models.Q(resource__icontains=q))
    entries = list(qs.order_by('-timestamp').values(
        'id', 'username', 'operation', 'resource_type', 'resource',
        'result', 'detail', 'timestamp', 'project__name',
    ))

    fmt = (format or 'csv').lower()

    if fmt == 'json':
        rows = []
        for e in entries:
            rows.append({
                'id': e['id'],
                'timestamp': e['timestamp'].isoformat(),
                'username': e['username'],
                'project': e['project__name'],
                'operation': e['operation'],
                'resource_type': e['resource_type'],
                'resource': e['resource'],
                'result': e['result'],
                'detail': e['detail'],
            })
        response = HttpResponse(_json.dumps(rows, indent=2), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="system-audit-log.json"'
        return response

    # CSV (default)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['id', 'timestamp', 'username', 'project', 'operation', 'resource_type', 'resource', 'result', 'detail'])
    for e in entries:
        writer.writerow([
            e['id'],
            e['timestamp'].isoformat(),
            e['username'],
            e['project__name'] or '',
            e['operation'],
            e['resource_type'],
            e['resource'],
            e['result'],
            _json.dumps(e['detail']) if e['detail'] else '',
        ])
    response = HttpResponse(buf.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="system-audit-log.csv"'
    return response


@router.get('/system/disk', response=dict, auth=session_mfa_auth)
def system_disk(request):
    """Return free/total bytes on the registry storage volume.

    For filesystem storage: reports disk usage of the mounted volume path.
    For S3 storage: disk metrics are not available — returns nulls.
    """
    import shutil
    from django.conf import settings as _s
    backend = getattr(_s, 'REGISTRY_STORAGE_BACKEND', 'filesystem')
    if backend == 's3':
        return {'total_bytes': None, 'free_bytes': None, 'used_bytes': None, 'storage_backend': 's3'}
    path = getattr(_s, 'REGISTRY_STORAGE_PATH', '/var/lib/registry')
    try:
        usage = shutil.disk_usage(path)
        return {'total_bytes': usage.total, 'free_bytes': usage.free, 'used_bytes': usage.used, 'storage_backend': 'filesystem'}
    except Exception:
        return {'total_bytes': None, 'free_bytes': None, 'used_bytes': None, 'storage_backend': 'filesystem'}


@router.get('/system/statistics', response=SystemStatsOut, auth=admin_session_auth)
def system_statistics(request):
    storage = Tag.objects.aggregate(total=Sum('size_bytes'))['total'] or 0
    return {
        'project_count': Project.objects.count(),
        'repository_count': Repository.objects.count(),
        'tag_count': Tag.objects.count(),
        'user_count': User.objects.count(),
        'storage_bytes': storage,
    }


@router.get('/system/activity', auth=admin_session_auth)
def system_activity(request, days: int = 365, projects: str = ''):
    """Daily push/pull counts across all projects over the last N days."""
    from django.utils import timezone
    from django.db.models.functions import TruncDate
    from django.db.models import Count, Q

    since = timezone.now() - timezone.timedelta(days=days)
    qs = AuditLog.objects.filter(timestamp__gte=since, operation__in=['push', 'pull'])
    if projects:
        project_list = [p.strip() for p in projects.split(',') if p.strip()]
        if project_list:
            qs = qs.filter(project__name__in=project_list)
    rows = (
        qs
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(
            pushes=Count('id', filter=Q(operation='push')),
            pulls=Count('id', filter=Q(operation='pull')),
        )
        .order_by('date')
    )
    return [
        {'date': str(r['date']), 'pushes': r['pushes'], 'pulls': r['pulls']}
        for r in rows
    ]


def _gc_config_dict(cfg) -> dict:
    return {
        'gc_enabled': cfg.gc_enabled,
        'gc_schedule_type': cfg.gc_schedule_type,
        'gc_interval_hours': cfg.gc_interval_hours,
        'gc_schedule_time': cfg.gc_schedule_time,
        'gc_schedule_day_of_week': cfg.gc_schedule_day_of_week,
        'gc_schedule_day_of_month': cfg.gc_schedule_day_of_month,
        'gc_last_run_at': cfg.gc_last_run_at,
    }


@router.get('/system/gc/config', response=GCConfigOut, auth=admin_session_auth)
def get_gc_config(request):
    return _gc_config_dict(SiteSettings.get())


@router.patch('/system/gc/config', response=GCConfigOut, auth=admin_session_auth)
def update_gc_config(request, payload: GCConfigIn):
    cfg = SiteSettings.get()
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return _gc_config_dict(cfg)
    import re as _re
    VALID_SCHEDULE_TYPES = {'hourly', 'every_n_hours', 'daily', 'weekly', 'monthly'}
    if payload.gc_enabled is not None:
        cfg.gc_enabled = payload.gc_enabled
    if payload.gc_schedule_type is not None:
        if payload.gc_schedule_type not in VALID_SCHEDULE_TYPES:
            raise HttpError(400, f'Invalid schedule type; must be one of {sorted(VALID_SCHEDULE_TYPES)}')
        cfg.gc_schedule_type = payload.gc_schedule_type
    if payload.gc_interval_hours is not None:
        if payload.gc_interval_hours < 1:
            raise HttpError(400, 'Interval must be at least 1 hour')
        cfg.gc_interval_hours = payload.gc_interval_hours
    if payload.gc_schedule_time is not None:
        if not _re.match(r'^\d{2}:\d{2}$', payload.gc_schedule_time):
            raise HttpError(400, 'gc_schedule_time must be HH:MM')
        cfg.gc_schedule_time = payload.gc_schedule_time
    if payload.gc_schedule_day_of_week is not None:
        if not 0 <= payload.gc_schedule_day_of_week <= 6:
            raise HttpError(400, 'gc_schedule_day_of_week must be 0–6 (Mon–Sun)')
        cfg.gc_schedule_day_of_week = payload.gc_schedule_day_of_week
    if payload.gc_schedule_day_of_month is not None:
        if not 1 <= payload.gc_schedule_day_of_month <= 28:
            raise HttpError(400, 'gc_schedule_day_of_month must be 1–28')
        cfg.gc_schedule_day_of_month = payload.gc_schedule_day_of_month
    cfg.save()
    log_action(request.auth, 'update', 'gc_config', 'system', {'changes': changes})
    return _gc_config_dict(cfg)


@router.post('/system/gc', response=GCJobOut, auth=admin_session_auth)
def trigger_gc(request):
    from registry.tasks import run_gc
    job = GCJob.objects.create(triggered_by='manual')
    log_action(request.auth, 'create', 'gc_run', 'system', {'job_id': job.pk})
    run_gc.apply_async(kwargs={'force': True, 'gc_job_id': job.pk}, queue='default')
    return job


@router.post('/system/gc/dry-run', response=GcDryRunOut, auth=admin_session_auth)
def gc_dry_run(request):
    """
    Simulate a GC sweep without deleting anything.

    Evaluates the same four phases as run_gc (phases 2–5):
      - Orphaned tag detection (tags in DB whose manifest no longer exists in registry)
      - Tag retention rule evaluation (which tags each project policy would delete)
      - Scan history pruning count (old finished/error rows that exceed the keep limit)
      - Audit and job log rotation count (rows older than the configured retention window)

    Blob GC (phase 6) cannot be dry-run — the `registry garbage-collect` binary has
    no preview mode.  The response omits it; the UI notes this explicitly.

    This endpoint is synchronous and read-only; it does not create a GCJob row.
    For large registries the orphan check can take a few seconds per repository.
    """
    import fnmatch as _fnmatch
    import requests as _req

    from registry.models import (
        Repository, Tag, ProjectPolicy, AuditLog,
        VulnerabilityScan, SecretScan, MisconfigScan,
        GCJob, SyncJob, TrivyUpdateJob, ReplicationJob,
    )
    from users.models import SiteSettings

    cfg = SiteSettings.get()
    registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://localhost:5000')

    orphan_tags: list[dict] = []
    retention_tags: list[dict] = []
    errors: list[str] = []

    # ── Phase 2: Orphaned tag detection ──────────────────────────────────────
    for repo in Repository.objects.select_related('project').iterator(chunk_size=100):
        repo_full = f'{repo.project.name}/{repo.name}'
        from registry.tasks import _registry_bearer_headers
        repo_headers = _registry_bearer_headers(f'repository:{repo_full}:pull')

        live_tags: set[str] = set()
        url: str | None = f'{registry_base}/v2/{repo_full}/tags/list?n=500'
        try:
            while url:
                r = _req.get(url, headers=repo_headers, timeout=15)
                if r.status_code == 404:
                    live_tags = set()
                    url = None
                    break
                r.raise_for_status()
                live_tags.update(r.json().get('tags') or [])
                link = r.headers.get('Link', '')
                if 'rel="next"' in link:
                    next_url = link.split(';')[0].strip().strip('<>')
                    url = next_url if next_url.startswith('http') else f'{registry_base}{next_url}'
                else:
                    url = None
        except Exception as exc:
            errors.append(f'Could not list tags for {repo_full}: {exc}')
            continue

        orphaned_qs = repo.tags.exclude(digest='').exclude(name__in=live_tags)
        for t in orphaned_qs.iterator(chunk_size=200):
            orphan_tags.append({
                'project': repo.project.name,
                'repo': repo.name,
                'tag': t.name,
                'reason': 'orphan',
                'rule_pattern': None,
            })

    # ── Phase 3: Tag retention rules ─────────────────────────────────────────
    for policy in ProjectPolicy.objects.select_related('project').filter(
        tag_retention_rules__isnull=False
    ).exclude(tag_retention_rules=[]):
        project = policy.project
        rules = policy.tag_retention_rules
        if not rules:
            continue

        for repo in project.repositories.all():
            tags_qs = list(repo.tags.order_by('-pushed_at'))
            claimed: set = set()

            for rule in rules:
                pattern = rule.get('match', '**')
                keep_count = rule.get('keep_count')
                keep_days = rule.get('keep_days')

                matching = [t for t in tags_qs if _fnmatch.fnmatch(t.name, pattern) and t.pk not in claimed]
                claimed.update(t.pk for t in matching)

                if keep_count is None and keep_days is None:
                    continue

                by_count: set | None = None
                by_days: set | None = None
                if keep_count is not None:
                    by_count = {t.pk for t in matching[keep_count:]}
                if keep_days is not None:
                    from django.utils import timezone as _tz
                    from datetime import timedelta as _td
                    cutoff = _tz.now() - _td(days=keep_days)
                    by_days = {t.pk for t in matching if t.pushed_at is not None and t.pushed_at < cutoff}

                if by_count is not None and by_days is not None:
                    to_delete = by_count & by_days
                elif by_count is not None:
                    to_delete = by_count
                elif by_days is not None:
                    to_delete = by_days
                else:
                    to_delete = set()

                for t in matching:
                    if t.pk in to_delete:
                        retention_tags.append({
                            'project': project.name,
                            'repo': repo.name,
                            'tag': t.name,
                            'reason': 'retention',
                            'rule_pattern': pattern,
                        })

    # ── Phase 4: Scan history pruning count ──────────────────────────────────
    _KEEP_FINISHED = 5
    _KEEP_ERROR = 1
    scans_to_prune = 0

    for ScanModel in (VulnerabilityScan, SecretScan, MisconfigScan):
        for status, keep_n in (('finished', _KEEP_FINISHED), ('error', _KEEP_ERROR)):
            all_rows = list(
                ScanModel.objects
                .filter(status=status)
                .order_by('tag_id', '-started_at')
                .values('pk', 'tag_id')
            )
            keep_pks: set[int] = set()
            prev_tag: int | None = None
            count = 0
            for row in all_rows:
                if row['tag_id'] != prev_tag:
                    prev_tag = row['tag_id']
                    count = 0
                if count < keep_n:
                    keep_pks.add(row['pk'])
                    count += 1
            scans_to_prune += ScanModel.objects.filter(status=status).exclude(pk__in=keep_pks).count()

    # ── Phase 5: Audit log rotation count ────────────────────────────────────
    audit_logs_to_prune = 0
    if cfg.audit_log_retention_days > 0:
        from django.utils import timezone as _tz
        from datetime import timedelta as _td
        cutoff = _tz.now() - _td(days=cfg.audit_log_retention_days)
        audit_logs_to_prune = AuditLog.objects.filter(timestamp__lt=cutoff).count()

    # ── Phase 5b: Job log rotation count ─────────────────────────────────────
    job_logs_to_prune = 0
    if cfg.job_log_retention_days > 0:
        from django.utils import timezone as _tz
        from datetime import timedelta as _td
        job_cutoff = _tz.now() - _td(days=cfg.job_log_retention_days)
        for model in (GCJob, SyncJob, TrivyUpdateJob, ReplicationJob):
            job_logs_to_prune += model.objects.filter(started_at__lt=job_cutoff).count()

    total = len(orphan_tags) + len(retention_tags)

    return {
        'orphan_tags': orphan_tags,
        'retention_tags': retention_tags,
        'scans_to_prune': scans_to_prune,
        'audit_logs_to_prune': audit_logs_to_prune,
        'job_logs_to_prune': job_logs_to_prune,
        'total_tags_to_delete': total,
        'errors': errors,
    }


@router.get('/system/gc/jobs', response=list[GCJobOut], auth=admin_session_auth)
def list_gc_jobs(request, limit: int = 20):
    return list(GCJob.objects.all()[:limit])


@router.get('/system/gc/jobs/latest', response=GCJobOut, auth=admin_session_auth)
def get_latest_gc_job(request):
    job = GCJob.objects.first()
    if not job:
        raise HttpError(404, 'No GC jobs found')
    return job


@router.post('/system/registry/sync', response=SyncJobOut, auth=admin_session_auth)
def sync_registry(request):
    from registry.models import SyncJob
    from registry.tasks import run_registry_sync
    log_action(request.auth, 'create', 'gc_run', 'system', {'type': 'catalog_sync'})
    job = SyncJob.objects.create()
    run_registry_sync.apply_async(kwargs={'sync_job_id': job.pk}, queue='default')
    return job


@router.get('/system/registry/sync/latest', response=SyncJobOut, auth=admin_session_auth)
def get_latest_sync_job(request):
    from registry.models import SyncJob
    job = SyncJob.objects.first()
    if job is None:
        raise HttpError(404, 'No sync jobs found')
    return job


# ── Trivy DB config ───────────────────────────────────────────────────────────

def _trivy_config_dict(cfg) -> dict:
    return {
        'trivy_db_update_enabled': cfg.trivy_db_update_enabled,
        'trivy_db_update_interval_hours': cfg.trivy_db_update_interval_hours,
        'trivy_db_last_updated_at': cfg.trivy_db_last_updated_at,
    }


@router.get('/system/trivy/config', response=TrivyConfigOut, auth=admin_session_auth)
def get_trivy_config(request):
    return _trivy_config_dict(SiteSettings.get())


@router.patch('/system/trivy/config', response=TrivyConfigOut, auth=admin_session_auth)
def update_trivy_config(request, payload: TrivyConfigIn):
    cfg = SiteSettings.get()
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return _trivy_config_dict(cfg)
    if payload.trivy_db_update_enabled is not None:
        cfg.trivy_db_update_enabled = payload.trivy_db_update_enabled
    if payload.trivy_db_update_interval_hours is not None:
        if payload.trivy_db_update_interval_hours < 1:
            raise HttpError(400, 'Interval must be at least 1 hour')
        cfg.trivy_db_update_interval_hours = payload.trivy_db_update_interval_hours
    cfg.save()
    log_action(request.auth, 'update', 'trivy_config', 'system', {'changes': changes})
    return _trivy_config_dict(cfg)


@router.post('/system/trivy/update', response=TrivyUpdateJobOut, auth=admin_session_auth)
def trigger_trivy_db_update(request):
    from registry.tasks import run_trivy_db_update
    job = TrivyUpdateJob.objects.create(triggered_by='manual')
    log_action(request.auth, 'create', 'trivy_db_update', 'system', {'job_id': job.pk})
    run_trivy_db_update.apply_async(kwargs={'force': True, 'trivy_job_id': job.pk}, queue='default')
    return job


@router.get('/system/trivy/jobs', response=list[TrivyUpdateJobOut], auth=admin_session_auth)
def list_trivy_jobs(request, limit: int = 20):
    return list(TrivyUpdateJob.objects.all()[:limit])


# ── Job log list endpoints ────────────────────────────────────────────────────

@router.get('/system/sync/jobs', response=list[SyncJobOut], auth=admin_session_auth)
def list_sync_jobs(request, limit: int = 50):
    from registry.models import SyncJob
    return list(SyncJob.objects.all()[:limit])


@router.get('/system/replications/all-jobs', response=list[ReplicationJobOut], auth=admin_session_auth)
def list_all_replication_jobs(request, limit: int = 50):
    from registry.models import ReplicationJob
    return list(ReplicationJob.objects.select_related('rule').all()[:limit])


# ── Labels (project-scoped) ───────────────────────────────────────────────────

@router.get('/projects/{project_name}/labels', response=list[LabelOut], auth=session_mfa_auth)
def list_labels(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return project.labels.all()


@router.post('/projects/{project_name}/labels', response={201: LabelOut}, auth=session_mfa_auth)
def create_label(request, project_name: str, payload: LabelIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    label = Label.objects.create(
        project=project,
        name=payload.name,
        description=payload.description,
        color=payload.color,
    )
    log_action(request.auth, 'create', 'label', payload.name,
               {'name': payload.name, 'color': payload.color}, project=project)
    return 201, label


@router.patch('/projects/{project_name}/labels/{label_id}', response=LabelOut, auth=session_mfa_auth)
def update_label(request, project_name: str, label_id: int, payload: LabelPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    label = get_object_or_404(Label, id=label_id, project=project)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return label
    for field, value in changes.items():
        setattr(label, field, value)
    label.save()
    log_action(request.auth, 'update', 'label', label.name, {'changes': changes}, project=project)
    return label


@router.delete('/projects/{project_name}/labels/{label_id}', response=MessageOut, auth=session_mfa_auth)
def delete_label(request, project_name: str, label_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    label = get_object_or_404(Label, id=label_id, project=project)
    log_action(request.auth, 'delete', 'label', label.name, {'name': label.name}, project=project)
    label.delete()
    return {'success': True, 'message': 'Label deleted'}


# ── Project Quota (project-scoped) ────────────────────────────────────────────

@router.get('/projects/{project_name}/quota', response=dict, auth=session_mfa_auth)
def get_quota(request, project_name: str):
    from django.db.models import Sum as _Sum
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    used = Tag.objects.filter(repository__project=project).aggregate(total=_Sum('size_bytes'))['total'] or 0
    return {
        'quota_gb': project.quota_gb,
        'used_bytes': used,
        'quota_bytes': int(project.quota_gb * 1024 ** 3) if project.quota_gb else None,
    }


@router.patch('/projects/{project_name}/quota', response=dict, auth=session_mfa_auth)
def set_quota(request, project_name: str, quota_gb: float | None = None):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    old_quota = project.quota_gb
    project.quota_gb = quota_gb
    project.save(update_fields=['quota_gb'])
    log_action(request.auth, 'update', 'quota', project_name,
               {'old_quota_gb': old_quota, 'new_quota_gb': quota_gb}, project=project)
    from django.db.models import Sum as _Sum
    used = Tag.objects.filter(repository__project=project).aggregate(total=_Sum('size_bytes'))['total'] or 0
    return {
        'quota_gb': project.quota_gb,
        'used_bytes': used,
        'quota_bytes': int(project.quota_gb * 1024 ** 3) if project.quota_gb else None,
    }


# ── Project Policy ────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/policy', response=ProjectPolicyOut, auth=session_mfa_auth)
def get_project_policy(request, project_name: str):
    """Return the policy for a project, creating defaults if not yet set."""
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    return policy


@router.patch('/projects/{project_name}/policy', response=ProjectPolicyOut, auth=session_mfa_auth)
def update_project_policy(request, project_name: str, payload: ProjectPolicyPatchIn):
    """Update one or more policy fields for a project. Requires project admin or system admin."""
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    valid_severities = {'critical', 'high', 'medium', 'low'}
    data = payload.dict(exclude_unset=True)
    if not data:
        return policy
    if 'vuln_block_rules' in data:
        rules = data['vuln_block_rules']
        bad = set(rules.keys()) - valid_severities
        if bad:
            raise HttpError(400, f'Invalid severity keys: {", ".join(bad)}. Must be: critical, high, medium, low')
        for sev, val in rules.items():
            if val is not None and not isinstance(val, int):
                raise HttpError(400, f'Value for "{sev}" must be an integer or null')
    if 'secret_block_threshold' in data and data['secret_block_threshold'] is not None:
        if not isinstance(data['secret_block_threshold'], int) or data['secret_block_threshold'] < 0:
            raise HttpError(400, 'secret_block_threshold must be a non-negative integer or null')
    if 'misconfig_fail_threshold' in data and data['misconfig_fail_threshold'] is not None:
        if not isinstance(data['misconfig_fail_threshold'], int) or data['misconfig_fail_threshold'] < 0:
            raise HttpError(400, 'misconfig_fail_threshold must be a non-negative integer or null')
    if 'tag_retention_rules' in data:
        if not isinstance(data['tag_retention_rules'], list):
            raise HttpError(400, 'tag_retention_rules must be a list')
        for i, rule in enumerate(data['tag_retention_rules']):
            if not isinstance(rule, dict):
                raise HttpError(400, f'tag_retention_rules[{i}] must be an object')
            if not rule.get('match', '').strip():
                raise HttpError(400, f'tag_retention_rules[{i}].match must be a non-empty string')
            keep_count = rule.get('keep_count')
            keep_days = rule.get('keep_days')
            if keep_count is None and keep_days is None:
                raise HttpError(400, f'tag_retention_rules[{i}] must specify keep_count, keep_days, or both')
            if keep_count is not None:
                if not isinstance(keep_count, int) or isinstance(keep_count, bool) or keep_count < 0:
                    raise HttpError(400, f'tag_retention_rules[{i}].keep_count must be a non-negative integer')
            if keep_days is not None:
                if not isinstance(keep_days, int) or isinstance(keep_days, bool) or keep_days < 1:
                    raise HttpError(400, f'tag_retention_rules[{i}].keep_days must be a positive integer')
    for field, value in data.items():
        setattr(policy, field, value)
    policy.save()
    log_action(request.auth, 'update', 'policy', project_name, {'changes': data}, project=project)
    return policy


# ── Tag retention preview (dry-run) ─────────────────────────────────────────

@router.post('/projects/{project_name}/policy/retention/preview', auth=session_mfa_auth)
def preview_retention_rule(request, project_name: str, payload: RetentionPreviewIn):
    """
    Dry-run a single retention rule against the project's current tags.

    Body: { match, keep_count?, keep_days? }
    Returns: { total_matched, total_deleted, repos: [ { repo, matched, deleted: [tag_name, …] } ] }
    """
    import fnmatch as _fnmatch
    from django.utils import timezone as _tz
    from datetime import timedelta

    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))

    pattern = payload.match.strip()
    if not pattern:
        raise HttpError(400, 'match must be a non-empty string')

    keep_count = payload.keep_count
    keep_days = payload.keep_days

    if keep_count is not None and keep_count < 0:
        raise HttpError(400, 'keep_count must be a non-negative integer')
    if keep_days is not None and keep_days < 1:
        raise HttpError(400, 'keep_days must be a positive integer')
    if keep_count is None and keep_days is None:
        raise HttpError(400, 'At least one of keep_count or keep_days is required')

    now = _tz.now()
    repos_out = []
    total_matched = 0
    total_deleted = 0

    for repo in project.repositories.prefetch_related('tags').order_by('name'):
        tags_qs = list(repo.tags.order_by('-pushed_at'))
        matching = [t for t in tags_qs if _fnmatch.fnmatch(t.name, pattern)]

        if not matching:
            continue

        by_count: set | None = None
        by_days: set | None = None
        if keep_count is not None:
            by_count = {t.pk for t in matching[keep_count:]}
        if keep_days is not None:
            cutoff = now - timedelta(days=keep_days)
            by_days = {t.pk for t in matching if t.pushed_at and t.pushed_at < cutoff}

        if by_count is not None and by_days is not None:
            to_delete_pks = by_count & by_days
        elif by_count is not None:
            to_delete_pks = by_count
        else:
            to_delete_pks = by_days  # type: ignore[assignment]

        deleted_tags = [t.name for t in matching if t.pk in to_delete_pks]
        kept_tags = [t.name for t in matching if t.pk not in to_delete_pks]

        total_matched += len(matching)
        total_deleted += len(deleted_tags)

        repos_out.append({
            'repo': repo.name,
            'matched': len(matching),
            'kept': kept_tags,
            'deleted': deleted_tags,
        })

    return {
        'total_matched': total_matched,
        'total_deleted': total_deleted,
        'repos': repos_out,
    }


# ── CVE Allowlist (project-scoped) ───────────────────────────────────────────

def _active_allowlist_ids(project, tag=None):
    """
    Return a set of lower-cased CVE IDs that are currently suppressed for the
    given scope.  Includes project-wide entries plus tag-specific entries when
    `tag` is provided.  Expired entries are excluded.
    """
    from django.utils import timezone as _tz
    now = _tz.now()
    qs = VulnAllowlistEntry.objects.filter(project=project).filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
    )
    if tag:
        qs = qs.filter(models.Q(tag__isnull=True) | models.Q(tag=tag))
    else:
        qs = qs.filter(tag__isnull=True)
    return {e.cve_id.lower() for e in qs}


def _apply_allowlist_to_counts(report, suppressed_ids, crit, high, med, low):
    """
    Given a scan report list and a set of suppressed CVE IDs (lower-cased),
    subtract suppressed findings from the raw severity counts.
    Returns (crit, high, med, low) adjusted downward, clamped to >= 0.
    Stored findings use snake_case keys (vulnerability_id, severity) from tasks.py.
    """
    if not suppressed_ids or not report:
        return crit, high, med, low
    for finding in report:
        vuln_id = (finding.get('vulnerability_id') or finding.get('VulnerabilityID') or finding.get('id') or '').lower()
        if vuln_id not in suppressed_ids:
            continue
        sev = (finding.get('severity') or finding.get('Severity') or '').lower()
        if sev == 'critical':
            crit = max(0, crit - 1)
        elif sev == 'high':
            high = max(0, high - 1)
        elif sev == 'medium':
            med = max(0, med - 1)
        elif sev == 'low':
            low = max(0, low - 1)
    return crit, high, med, low


@router.get('/projects/{project_name}/allowlist', response=list[VulnAllowlistOut], auth=session_mfa_auth)
def list_allowlist(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return VulnAllowlistEntry.objects.filter(project=project).select_related('tag', 'added_by')


@router.post('/projects/{project_name}/allowlist', response={201: VulnAllowlistOut}, auth=session_mfa_auth)
def create_allowlist_entry(request, project_name: str, payload: VulnAllowlistIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    tag = None
    if payload.tag_id:
        tag = get_object_or_404(Tag, id=payload.tag_id, repository__project=project)
    try:
        entry = VulnAllowlistEntry.objects.create(
            project=project,
            tag=tag,
            cve_id=payload.cve_id.strip().upper(),
            reason=payload.reason,
            expires_at=payload.expires_at,
            added_by=request.auth if hasattr(request.auth, 'username') else None,
        )
    except Exception as _e:
        if 'unique' not in str(_e).lower() and 'duplicate' not in str(_e).lower():
            raise
        raise HttpError(409, 'An allowlist entry for this CVE already exists in this scope')
    log_action(request.auth, 'create', 'allowlist', payload.cve_id,
               {'scope': 'tag' if tag else 'project', 'tag': str(tag) if tag else None}, project=project)
    return 201, entry


@router.patch('/projects/{project_name}/allowlist/{entry_id}', response=VulnAllowlistOut, auth=session_mfa_auth)
def update_allowlist_entry(request, project_name: str, entry_id: int, payload: VulnAllowlistPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    entry = get_object_or_404(VulnAllowlistEntry, id=entry_id, project=project)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return entry
    for field, value in changes.items():
        setattr(entry, field, value)
    entry.save()
    log_action(request.auth, 'update', 'allowlist', entry.cve_id, {'changes': changes}, project=project)
    return entry


@router.delete('/projects/{project_name}/allowlist/{entry_id}', response=MessageOut, auth=session_mfa_auth)
def delete_allowlist_entry(request, project_name: str, entry_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    entry = get_object_or_404(VulnAllowlistEntry, id=entry_id, project=project)
    log_action(request.auth, 'delete', 'allowlist', entry.cve_id,
               {'scope': 'tag' if entry.tag_id else 'project'}, project=project)
    entry.delete()
    return {'success': True, 'message': 'Allowlist entry deleted'}


# ── Secret Allowlist (tag-scoped only) ───────────────────────────────────────

def _active_secret_allowlist_ids(tag):
    """Return a set of lower-cased rule_ids that are suppressed for the given tag.
    Includes both project-wide entries (tag=None on the project) and tag-specific entries."""
    from django.utils import timezone as _tz
    now = _tz.now()
    project = tag.repository.project
    qs = SecretAllowlistEntry.objects.filter(
        models.Q(project=project, tag__isnull=True) | models.Q(tag=tag)
    ).filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
    )
    return {e.rule_id.lower() for e in qs}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/secret-allowlist',
            response=list[SecretAllowlistOut], auth=session_mfa_auth)
def list_secret_allowlist(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    return SecretAllowlistEntry.objects.filter(tag=tag).select_related('added_by')


@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/secret-allowlist',
             response={201: SecretAllowlistOut}, auth=session_mfa_auth)
def create_secret_allowlist_entry(request, project_name: str, repo_name: str, tag_name: str,
                                  payload: SecretAllowlistIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    try:
        entry = SecretAllowlistEntry.objects.create(
            project=project,
            tag=tag,
            rule_id=payload.rule_id.strip().lower(),
            reason=payload.reason,
            expires_at=payload.expires_at,
            added_by=request.auth if hasattr(request.auth, 'username') else None,
        )
    except Exception as _e:
        if 'unique' not in str(_e).lower() and 'duplicate' not in str(_e).lower():
            raise
        raise HttpError(409, 'An allowlist entry for this rule already exists on this image')
    log_action(request.auth, 'create', 'secret-allowlist', payload.rule_id,
               {'tag': tag_name, 'repository': repo_name}, project=project)
    return 201, entry


@router.patch('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/secret-allowlist/{entry_id}',
              response=SecretAllowlistOut, auth=session_mfa_auth)
def update_secret_allowlist_entry(request, project_name: str, repo_name: str, tag_name: str,
                                  entry_id: int, payload: SecretAllowlistPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    entry = get_object_or_404(SecretAllowlistEntry, id=entry_id, tag=tag)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return entry
    for field, value in changes.items():
        setattr(entry, field, value)
    entry.save()
    return entry


@router.delete('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/secret-allowlist/{entry_id}',
               response=MessageOut, auth=session_mfa_auth)
def delete_secret_allowlist_entry(request, project_name: str, repo_name: str, tag_name: str,
                                  entry_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    entry = get_object_or_404(SecretAllowlistEntry, id=entry_id, tag=tag)
    log_action(request.auth, 'delete', 'secret-allowlist', entry.rule_id,
               {'tag': tag_name, 'repository': repo_name}, project=project)
    entry.delete()
    return {'success': True, 'message': 'Secret allowlist entry deleted'}


# ── Secret Allowlist (project-wide) ──────────────────────────────────────────

@router.get('/projects/{project_name}/secret-allowlist', response=list[SecretAllowlistOut], auth=session_mfa_auth)
def list_project_secret_allowlist(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return SecretAllowlistEntry.objects.filter(project=project, tag__isnull=True).select_related('added_by')


@router.post('/projects/{project_name}/secret-allowlist', response={201: SecretAllowlistOut}, auth=session_mfa_auth)
def create_project_secret_allowlist_entry(request, project_name: str, payload: SecretAllowlistIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    try:
        entry = SecretAllowlistEntry.objects.create(
            project=project,
            tag=None,
            rule_id=payload.rule_id.strip().lower(),
            reason=payload.reason,
            expires_at=payload.expires_at,
            added_by=request.auth if hasattr(request.auth, 'username') else None,
        )
    except Exception as _e:
        if 'unique' not in str(_e).lower() and 'duplicate' not in str(_e).lower():
            raise
        raise HttpError(409, 'A project-wide allowlist entry for this rule already exists')
    log_action(request.auth, 'create', 'secret-allowlist', payload.rule_id,
               {'scope': 'project'}, project=project)
    return 201, entry


@router.delete('/projects/{project_name}/secret-allowlist/{entry_id}', response=MessageOut, auth=session_mfa_auth)
def delete_project_secret_allowlist_entry(request, project_name: str, entry_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    entry = get_object_or_404(SecretAllowlistEntry, id=entry_id, project=project, tag__isnull=True)
    log_action(request.auth, 'delete', 'secret-allowlist', entry.rule_id,
               {'scope': 'project'}, project=project)
    entry.delete()
    return {'success': True, 'message': 'Secret allowlist entry deleted'}


# ── Misconfig Allowlist (tag-scoped only) ─────────────────────────────────────

def _active_misconfig_allowlist_ids(tag):
    """Return a set of lower-cased check_ids that are suppressed for the given tag.
    Includes both project-wide entries (tag=None on the project) and tag-specific entries."""
    from django.utils import timezone as _tz
    now = _tz.now()
    project = tag.repository.project
    qs = MisconfigAllowlistEntry.objects.filter(
        models.Q(project=project, tag__isnull=True) | models.Q(tag=tag)
    ).filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
    )
    return {e.check_id.lower() for e in qs}


@router.get('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/misconfig-allowlist',
            response=list[MisconfigAllowlistOut], auth=session_mfa_auth)
def list_misconfig_allowlist(request, project_name: str, repo_name: str, tag_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    return MisconfigAllowlistEntry.objects.filter(tag=tag).select_related('added_by')


@router.post('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/misconfig-allowlist',
             response={201: MisconfigAllowlistOut}, auth=session_mfa_auth)
def create_misconfig_allowlist_entry(request, project_name: str, repo_name: str, tag_name: str,
                                     payload: MisconfigAllowlistIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    try:
        entry = MisconfigAllowlistEntry.objects.create(
            project=project,
            tag=tag,
            check_id=payload.check_id.strip().upper(),
            reason=payload.reason,
            expires_at=payload.expires_at,
            added_by=request.auth if hasattr(request.auth, 'username') else None,
        )
    except Exception as _e:
        if 'unique' not in str(_e).lower() and 'duplicate' not in str(_e).lower():
            raise
        raise HttpError(409, 'An allowlist entry for this check already exists on this image')
    log_action(request.auth, 'create', 'misconfig-allowlist', payload.check_id,
               {'tag': tag_name, 'repository': repo_name}, project=project)
    return 201, entry


@router.patch('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/misconfig-allowlist/{entry_id}',
              response=MisconfigAllowlistOut, auth=session_mfa_auth)
def update_misconfig_allowlist_entry(request, project_name: str, repo_name: str, tag_name: str,
                                     entry_id: int, payload: MisconfigAllowlistPatchIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    entry = get_object_or_404(MisconfigAllowlistEntry, id=entry_id, tag=tag)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return entry
    for field, value in changes.items():
        setattr(entry, field, value)
    entry.save()
    return entry


@router.delete('/projects/{project_name}/repositories/{repo_name}/tags/{tag_name}/misconfig-allowlist/{entry_id}',
               response=MessageOut, auth=session_mfa_auth)
def delete_misconfig_allowlist_entry(request, project_name: str, repo_name: str, tag_name: str,
                                     entry_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    tag = get_object_or_404(Tag, repository=repo, name=tag_name)
    entry = get_object_or_404(MisconfigAllowlistEntry, id=entry_id, tag=tag)
    log_action(request.auth, 'delete', 'misconfig-allowlist', entry.check_id,
               {'tag': tag_name, 'repository': repo_name}, project=project)
    entry.delete()
    return {'success': True, 'message': 'Misconfig allowlist entry deleted'}


# ── Misconfig Allowlist (project-wide) ───────────────────────────────────────

@router.get('/projects/{project_name}/misconfig-allowlist', response=list[MisconfigAllowlistOut], auth=session_mfa_auth)
def list_project_misconfig_allowlist(request, project_name: str):
    project = get_object_or_404(Project, name=project_name)
    require(can_pull(request.auth, project))
    return MisconfigAllowlistEntry.objects.filter(project=project, tag__isnull=True).select_related('added_by')


@router.post('/projects/{project_name}/misconfig-allowlist', response={201: MisconfigAllowlistOut}, auth=session_mfa_auth)
def create_project_misconfig_allowlist_entry(request, project_name: str, payload: MisconfigAllowlistIn):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    try:
        entry = MisconfigAllowlistEntry.objects.create(
            project=project,
            tag=None,
            check_id=payload.check_id.strip().upper(),
            reason=payload.reason,
            expires_at=payload.expires_at,
            added_by=request.auth if hasattr(request.auth, 'username') else None,
        )
    except Exception as _e:
        if 'unique' not in str(_e).lower() and 'duplicate' not in str(_e).lower():
            raise
        raise HttpError(409, 'A project-wide allowlist entry for this check already exists')
    log_action(request.auth, 'create', 'misconfig-allowlist', payload.check_id,
               {'scope': 'project'}, project=project)
    return 201, entry


@router.delete('/projects/{project_name}/misconfig-allowlist/{entry_id}', response=MessageOut, auth=session_mfa_auth)
def delete_project_misconfig_allowlist_entry(request, project_name: str, entry_id: int):
    project = get_object_or_404(Project, name=project_name)
    require(can_manage_project(request.auth, project))
    entry = get_object_or_404(MisconfigAllowlistEntry, id=entry_id, project=project, tag__isnull=True)
    log_action(request.auth, 'delete', 'misconfig-allowlist', entry.check_id,
               {'scope': 'project'}, project=project)
    entry.delete()
    return {'success': True, 'message': 'Misconfig allowlist entry deleted'}


# ── Remote Registries (system-scoped) ────────────────────────────────────────

@router.get('/system/remote-registries', response=list[RemoteRegistryOut], auth=admin_session_auth)
def list_remote_registries(request):
    return RemoteRegistry.objects.all()


@router.post('/system/remote-registries', response={201: RemoteRegistryOut}, auth=admin_session_auth)
def create_remote_registry(request, payload: RemoteRegistryIn):
    remote = RemoteRegistry(
        name=payload.name,
        description=payload.description,
        registry_type=payload.registry_type,
        endpoint=payload.endpoint,
        username=payload.username,
        insecure=payload.insecure,
        verified=False,  # always unverified until explicitly pinged
    )
    remote.set_password(payload.password)
    remote.save()
    log_action(request.auth, 'create', 'remote_registry', remote.name,
               {'name': remote.name, 'registry_type': remote.registry_type, 'endpoint': remote.endpoint})
    return 201, remote

# Fields that affect connectivity — saving any of these invalidates the last ping result
_CREDENTIAL_FIELDS = {'endpoint', 'username', 'password', 'insecure', 'registry_type'}

@router.patch('/system/remote-registries/{remote_id}', response=RemoteRegistryOut, auth=admin_session_auth)
def update_remote_registry(request, remote_id: int, payload: RemoteRegistryPatchIn):
    remote = get_object_or_404(RemoteRegistry, id=remote_id)
    data = payload.dict(exclude_unset=True)
    if not data:
        return remote
    if 'password' in data:
        remote.set_password(data.pop('password'))
    for field, value in data.items():
        setattr(remote, field, value)
    # If any credential or connectivity field changed, invalidate the verified status
    if data.keys() & _CREDENTIAL_FIELDS:
        remote.verified = False
    remote.save()
    log_action(request.auth, 'update', 'remote_registry', remote.name,
               {'name': remote.name, 'changes': list(data.keys())})
    return remote


@router.delete('/system/remote-registries/{remote_id}', response=MessageOut, auth=admin_session_auth)
def delete_remote_registry(request, remote_id: int):
    remote = get_object_or_404(RemoteRegistry, id=remote_id)
    log_action(request.auth, 'delete', 'remote_registry', remote.name,
               {'name': remote.name, 'registry_type': remote.registry_type})
    remote.delete()
    return {'success': True, 'message': 'Remote registry deleted'}


@router.post('/system/remote-registries/{remote_id}/ping', response={200: MessageOut, 502: MessageOut}, auth=admin_session_auth)
def ping_remote_registry(request, remote_id: int):
    """Verify connectivity and credentials for a remote registry."""
    import urllib.request
    import urllib.error
    import ssl
    import base64
    import json

    remote = get_object_or_404(RemoteRegistry, id=remote_id)
    _plaintext_password = remote.get_password()
    has_creds = bool(remote.username and _plaintext_password)

    def _save(verified: bool):
        remote.verified = verified
        remote.save(update_fields=['verified'])

    def _basic_header():
        cred = base64.b64encode(
            f'{remote.username}:{_plaintext_password}'.encode()
        ).decode()
        return f'Basic {cred}'

    def _ctx():
        ctx = ssl.create_default_context()
        if remote.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get(url, headers=None):
        req = urllib.request.Request(url, headers={'User-Agent': 'siene/1.0', **(headers or {})})
        return urllib.request.urlopen(req, context=_ctx(), timeout=8)

    # ── ECR: validate via AWS GetAuthorizationToken API (SigV4) ──────────────
    if remote.registry_type == 'ecr':
        if not has_creds:
            # Just check the endpoint is reachable (will 401, which means it's there)
            try:
                _get(remote.endpoint.rstrip('/') + '/v2/')
                _save(True)
                return 200, {'success': True, 'message': 'Registry reachable (no credentials configured)'}
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    _save(True)
                    return 200, {'success': True, 'message': 'Registry reachable (no credentials configured)'}
                _save(False)
                return 502, {'success': False, 'message': f'Registry returned HTTP {e.code}'}
            except Exception as e:
                _save(False)
                return 502, {'success': False, 'message': f'Connection failed: {e}'}

        # Parse region from endpoint: https://<acct>.dkr.ecr.<region>.amazonaws.com
        import hmac, hashlib, datetime
        try:
            region = remote.endpoint.split('.ecr.')[1].split('.amazonaws.com')[0]
        except (IndexError, AttributeError):
            _save(False)
            return 502, {'success': False, 'message': 'Could not determine AWS region from endpoint URL'}

        # AWS SigV4 for ecr:GetAuthorizationToken
        access_key = remote.username
        secret_key = _plaintext_password
        service = 'ecr'
        host = f'ecr.{region}.amazonaws.com'
        endpoint_url = f'https://{host}/'

        now = datetime.datetime.utcnow()
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = now.strftime('%Y%m%d')

        payload = '{}'
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()

        canonical_headers = f'content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-target:AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken\n'
        signed_headers = 'content-type;host;x-amz-date;x-amz-target'
        canonical_request = f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'

        credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
        string_to_sign = f'AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}'

        def _sign(key, msg):
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        signing_key = _sign(
            _sign(_sign(_sign(f'AWS4{secret_key}'.encode(), date_stamp), region), service),
            'aws4_request',
        )
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()


        auth_header = (
            f'AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )

        try:
            req = urllib.request.Request(
                endpoint_url,
                data=payload.encode(),
                headers={
                    'User-Agent': 'siene/1.0',
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Date': amz_date,
                    'X-Amz-Target': 'AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken',
                    'Authorization': auth_header,
                },
            )
            urllib.request.urlopen(req, context=_ctx(), timeout=8)
            _save(True)
            return 200, {'success': True, 'message': 'AWS credentials valid'}
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace')
            if e.code in (400, 403):
                _save(False)
                try:
                    msg = json.loads(body).get('message') or json.loads(body).get('__type', '')
                except Exception:
                    msg = body[:120]
                return 502, {'success': False, 'message': f'AWS authentication failed: {msg}'}
            _save(False)
            return 502, {'success': False, 'message': f'AWS API error HTTP {e.code}'}
        except Exception as e:
            _save(False)
            return 502, {'success': False, 'message': f'Connection failed: {e}'}

    # ── Docker Hub: validate via token endpoint ───────────────────────────────
    if remote.registry_type == 'docker-hub':
        if not has_creds:
            try:
                _get('https://hub.docker.com')
                _save(True)
                return 200, {'success': True, 'message': 'Docker Hub reachable (no credentials configured)'}
            except Exception as e:
                _save(False)
                return 502, {'success': False, 'message': f'Connection failed: {e}'}
        try:
            token_url = (
                f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull'
            )
            _get(token_url, {'Authorization': _basic_header()})
            _save(True)
            return 200, {'success': True, 'message': 'Docker Hub credentials valid'}
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                _save(False)
                return 502, {'success': False, 'message': 'Authentication failed — check your Docker Hub username and password/token'}
            _save(False)
            return 502, {'success': False, 'message': f'Docker Hub returned HTTP {e.code}'}
        except Exception as e:
            _save(False)
            return 502, {'success': False, 'message': f'Connection failed: {e}'}

    # ── GCR: reachability only (auth uses service account JSON, too complex to validate here) ──
    if remote.registry_type == 'gcr':
        try:
            _get(remote.endpoint.rstrip('/') + '/v2/')
            _save(True)
            return 200, {'success': True, 'message': 'GCR reachable'}
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                _save(True)
                return 200, {'success': True, 'message': 'GCR reachable (credentials not validated — use gcloud to verify)'}
            _save(False)
            return 502, {'success': False, 'message': f'GCR returned HTTP {e.code}'}
        except Exception as e:
            _save(False)
            return 502, {'success': False, 'message': f'Connection failed: {e}'}

    # ── All other types: standard Docker v2 Basic auth against /v2/ ──────────
    try:
        ping_url = remote.endpoint.rstrip('/') + '/v2/'
        headers = {}
        if has_creds:
            headers['Authorization'] = _basic_header()
        try:
            _get(ping_url, headers)
            _save(True)
            return 200, {'success': True, 'message': 'Connected successfully'}
        except urllib.error.HTTPError as http_err:
            if http_err.code in (401, 403):
                if has_creds:
                    _save(False)
                    return 502, {'success': False, 'message': f'Authentication failed (HTTP {http_err.code}) — check your credentials'}
                else:
                    _save(True)
                    return 200, {'success': True, 'message': 'Registry reachable (no credentials configured)'}
            raise
    except urllib.error.HTTPError as e:
        _save(False)
        return 502, {'success': False, 'message': f'Registry returned HTTP {e.code}: {e.reason}'}
    except urllib.error.URLError as e:
        _save(False)
        return 502, {'success': False, 'message': f'Connection failed: {e.reason}'}
    except Exception as e:
        _save(False)
        return 502, {'success': False, 'message': f'Unreachable: {e}'}


# ── Replication Rules (system-scoped) ─────────────────────────────────────────

def _sync_replication_schedule(rule: 'ReplicationRule') -> None:
    """Create, update, or delete the django-celery-beat PeriodicTask that
    drives a scheduled ReplicationRule.

    Rules with trigger='scheduled' get a CrontabSchedule + PeriodicTask named
    ``replication-rule-<id>``.  Any other trigger (manual, on_push) or a
    disabled rule gets the task removed.  Errors are swallowed so they never
    break the API response.
    """
    try:
        from django_celery_beat.models import CrontabSchedule, PeriodicTask
        import json as _json

        task_name = f'replication-rule-{rule.pk}'

        if rule.trigger != ReplicationRule.TRIGGER_SCHEDULED or not rule.enabled or not rule.schedule:
            # Remove any existing periodic task for this rule
            PeriodicTask.objects.filter(name=task_name).delete()
            return

        # Parse "minute hour dom month dow" cron expression (5 fields)
        parts = rule.schedule.strip().split()
        if len(parts) != 5:
            # Malformed cron — remove stale task and bail
            PeriodicTask.objects.filter(name=task_name).delete()
            return

        minute, hour, dom, month, dow = parts
        crontab, _ = CrontabSchedule.objects.get_or_create(
            minute=minute,
            hour=hour,
            day_of_week=dow,
            day_of_month=dom,
            month_of_year=month,
        )
        PeriodicTask.objects.update_or_create(
            name=task_name,
            defaults={
                'task': 'registry.tasks.run_replication',
                'crontab': crontab,
                'args': _json.dumps([rule.pk]),
                'kwargs': _json.dumps({}),
                'enabled': True,
            },
        )
    except Exception:
        pass


@router.get('/system/replications', response=list[ReplicationRuleOut], auth=admin_session_auth)
def list_replications(request):
    return ReplicationRule.objects.select_related('remote').all()


@router.post('/system/replications', response={201: ReplicationRuleOut}, auth=admin_session_auth)
def create_replication(request, payload: ReplicationRuleIn):
    remote = get_object_or_404(RemoteRegistry, id=payload.remote_id)
    rule = ReplicationRule.objects.create(
        name=payload.name,
        description=payload.description,
        remote=remote,
        direction=payload.direction,
        source_filter=payload.source_filter,
        tag_filter=payload.tag_filter,
        label_filter=payload.label_filter,
        resource_type=payload.resource_type,
        destination_namespace=payload.destination_namespace,
        flatten_mode=payload.flatten_mode,
        trigger=payload.trigger,
        schedule=payload.schedule,
        bandwidth_limit_kb=payload.bandwidth_limit_kb,
        override_existing=payload.override_existing,
        single_active=payload.single_active,
        enabled=payload.enabled,
        delete_remote_on_local_delete=payload.delete_remote_on_local_delete,
    )
    log_action(request.auth, 'create', 'replication', rule.name,
               {'name': rule.name, 'direction': rule.direction, 'trigger': rule.trigger})
    _sync_replication_schedule(rule)
    return 201, rule


@router.patch('/system/replications/{rule_id}', response=ReplicationRuleOut, auth=admin_session_auth)
def update_replication(request, rule_id: int, payload: ReplicationRulePatchIn):
    rule = get_object_or_404(ReplicationRule, id=rule_id)
    changes = payload.dict(exclude_unset=True)
    if not changes:
        return rule
    for field, value in changes.items():
        setattr(rule, field, value)
    rule.save()
    log_action(request.auth, 'update', 'replication', rule.name, {'changes': changes})
    _sync_replication_schedule(rule)
    return rule


@router.delete('/system/replications/{rule_id}', response=MessageOut, auth=admin_session_auth)
def delete_replication(request, rule_id: int):
    rule = get_object_or_404(ReplicationRule, id=rule_id)
    log_action(request.auth, 'delete', 'replication', rule.name, {'name': rule.name})
    # Remove the associated PeriodicTask (if any) before deleting the rule row.
    try:
        from django_celery_beat.models import PeriodicTask as _PT
        _PT.objects.filter(name=f'replication-rule-{rule.pk}').delete()
    except Exception:
        pass
    rule.delete()
    return {'success': True, 'message': 'Replication rule deleted'}


@router.post('/system/replications/{rule_id}/execute', response=MessageOut, auth=admin_session_auth)
def execute_replication(request, rule_id: int):
    from django.utils import timezone as _tz
    from registry.tasks import run_replication
    rule = get_object_or_404(ReplicationRule, id=rule_id)
    rule.last_run_at = _tz.now()
    rule.last_run_status = 'triggered'
    rule.save(update_fields=['last_run_at', 'last_run_status'])
    run_replication.apply_async(args=[rule_id], queue="default")
    return {'success': True, 'message': f'Replication "{rule.name}" triggered'}


@router.get('/system/replications/{rule_id}/jobs', response=list[ReplicationJobOut], auth=admin_session_auth)
def list_replication_jobs(request, rule_id: int):
    from registry.models import ReplicationJob
    get_object_or_404(ReplicationRule, id=rule_id)
    return ReplicationJob.objects.filter(rule_id=rule_id).order_by('-started_at')[:50]


@router.get('/system/replications/{rule_id}/jobs/{job_id}', response=ReplicationJobOut, auth=admin_session_auth)
def get_replication_job(request, rule_id: int, job_id: int):
    from registry.models import ReplicationJob
    return get_object_or_404(ReplicationJob, id=job_id, rule_id=rule_id)


# ── Security Hub (system-scoped) ──────────────────────────────────────────────

@router.get('/system/security', response=list[VulnSummaryOut], auth=admin_session_auth)
def security_hub(request, project: str = '', severity: str = ''):
    """Aggregate vulnerability summary across all tags with completed scans."""
    scans = VulnerabilityScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished').order_by('-finished_at')

    if project:
        scans = scans.filter(tag__repository__project__name=project)

    # Pre-fetch all active allowlist entries in scope (avoids N+1)
    from django.utils import timezone as _tz
    _now = _tz.now()
    al_qs = VulnAllowlistEntry.objects.filter(
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=_now)
    ).values('cve_id', 'tag_id', 'project_id')
    if project:
        al_qs = al_qs.filter(project__name=project)
    # project-wide ids keyed by project pk
    proj_wide: dict[int, set[str]] = {}
    tag_spec: dict[int, set[str]] = {}
    for e in al_qs:
        if e['tag_id'] is None:
            proj_wide.setdefault(e['project_id'], set()).add(e['cve_id'].lower())
        else:
            tag_spec.setdefault(e['tag_id'], set()).add(e['cve_id'].lower())

    results = []
    seen_tags: set[int] = set()

    for scan in scans:
        tag = scan.tag
        if tag.id in seen_tags:
            continue
        seen_tags.add(tag.id)

        summary = scan.summary or {}
        crit = summary.get('critical', 0) or summary.get('CRITICAL', 0)
        high = summary.get('high', 0) or summary.get('HIGH', 0)
        med  = summary.get('medium', 0) or summary.get('MEDIUM', 0)
        low  = summary.get('low', 0) or summary.get('LOW', 0)

        # Subtract allowlisted CVEs from counts
        proj_id = tag.repository.project_id
        suppressed_ids = proj_wide.get(proj_id, set()) | tag_spec.get(tag.id, set())
        if suppressed_ids and scan.report:
            crit, high, med, low = _apply_allowlist_to_counts(
                scan.report, suppressed_ids, crit, high, med, low
            )

        # Filter by severity if requested
        if severity == 'critical' and crit == 0:
            continue
        if severity == 'high' and crit + high == 0:
            continue

        results.append({
            'tag_id': tag.id,
            'tag_name': tag.name,
            'repository': tag.repository.name,
            'project': tag.repository.project.name,
            'scan_status': scan.status,
            'critical': crit,
            'high': high,
            'medium': med,
            'low': low,
            'scanned_at': scan.finished_at,
        })

    return results
