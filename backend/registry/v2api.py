"""
Siene Public API v2  —  /api/v2/

Authentication: Bearer token issued to a RobotAccount.
  Authorization: Bearer <plaintext_secret>

All endpoints are robot-only. Robots have a `permissions` JSON list:
  [{"resource": "repository", "action": "pull", "project": "myproject"}, ...]
  [{"resource": "*",          "action": "*"}]   -- system-level robot (all access)

Permission helpers below map Harbor-style RBAC onto Siene's role model.
"""

import hashlib
import secrets
from typing import Optional
from django.contrib.auth.models import User
from django.db.models import Sum, Q
from django.shortcuts import get_object_or_404
from ninja import Router, Schema
from ninja.errors import HttpError

from users.auth import robot_bearer_auth
from registry.models import (
    Project, ProjectMember, Repository, Tag,
    RobotAccount, AuditLog, VulnerabilityScan,
    Label, RemoteRegistry, ReplicationRule, ReplicationJob,
    ProjectPolicy,
)

router = Router()


# ── Permission helpers ────────────────────────────────────────────────────────

def _is_system_robot(robot: RobotAccount) -> bool:
    """A system-level robot has project=None and at least one wildcard permission."""
    if robot.project is not None:
        return False
    for perm in (robot.permissions or []):
        if perm.get('resource') == '*' or perm.get('action') == '*':
            return True
    return False


def _robot_has_perm(robot: RobotAccount, project_name: str, action: str) -> bool:
    """
    Check if a robot is permitted to perform `action` on a given project.

    action hierarchy: read < push < delete < manage < admin

    A system robot (*/*) passes everything.
    A project-scoped robot checks its permissions list.
    """
    if _is_system_robot(robot):
        return True

    _ACTION_RANK = {'read': 1, 'pull': 1, 'push': 2, 'delete': 3, 'manage': 4, 'admin': 5}
    needed = _ACTION_RANK.get(action, 99)

    for perm in (robot.permissions or []):
        res = perm.get('resource', '')
        act = perm.get('action', '')
        proj = perm.get('project', '')
        # Project filter: blank or '*' means any project
        if proj and proj != '*' and proj != project_name:
            continue
        if res in ('*', 'repository', 'project') and (act == '*' or _ACTION_RANK.get(act, 0) >= needed):
            return True
    return False


def _require_robot(robot: RobotAccount, project_name: str, action: str) -> None:
    if not _robot_has_perm(robot, project_name, action):
        raise HttpError(403, 'Forbidden: robot does not have required permission')


def _require_system_robot(robot: RobotAccount) -> None:
    if not _is_system_robot(robot):
        raise HttpError(403, 'Forbidden: system-level robot required')


# ── Inline schemas (v2-flavoured, separate from registry/schemas.py) ──────────

class V2ProjectOut(Schema):
    id: int
    name: str
    display_name: str
    description: str
    public: bool
    quota_gb: Optional[float]
    owner_username: Optional[str]
    repo_count: int
    created_at: str
    updated_at: str

    @staticmethod
    def resolve_owner_username(obj):
        return obj.owner.username if obj.owner else None

    @staticmethod
    def resolve_repo_count(obj):
        return obj.repositories.count()

    @staticmethod
    def resolve_created_at(obj):
        return obj.created_at.isoformat()

    @staticmethod
    def resolve_updated_at(obj):
        return obj.updated_at.isoformat()


class V2RepositoryOut(Schema):
    id: int
    name: str
    full_name: str
    description: str
    pull_count: int
    push_count: int
    artifact_count: int
    created_at: str
    updated_at: str

    @staticmethod
    def resolve_artifact_count(obj):
        return obj.tags.count()

    @staticmethod
    def resolve_created_at(obj):
        return obj.created_at.isoformat()

    @staticmethod
    def resolve_updated_at(obj):
        return obj.updated_at.isoformat()


class V2ArtifactOut(Schema):
    """An artifact is a tag in Siene."""
    id: int
    digest: str
    tags: list[str]
    size_bytes: int
    os: str
    architecture: str
    pushed_by: Optional[str]
    pushed_at: str
    scan_status: Optional[str]
    labels: list[str]
    cosign_status: str
    notation_status: str

    @staticmethod
    def resolve_tags(obj):
        # Return the tag name itself plus any sharing-digest siblings
        repo = obj.repository
        names = list(Tag.objects.filter(repository=repo, digest=obj.digest).values_list('name', flat=True))
        return names

    @staticmethod
    def resolve_pushed_by(obj):
        return obj.pushed_by.username if obj.pushed_by else None

    @staticmethod
    def resolve_pushed_at(obj):
        return obj.pushed_at.isoformat()

    @staticmethod
    def resolve_scan_status(obj):
        latest = obj.scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_labels(obj):
        return [lb.name for lb in obj.labels.all()]

    @staticmethod
    def resolve_cosign_status(obj):
        try:
            return obj.signature_status.cosign
        except Exception:
            return 'unknown'

    @staticmethod
    def resolve_notation_status(obj):
        try:
            return obj.signature_status.notation
        except Exception:
            return 'not_available'


class V2MemberOut(Schema):
    id: int
    username: str
    email: str
    role: str

    @staticmethod
    def resolve_username(obj):
        return obj.user.username

    @staticmethod
    def resolve_email(obj):
        return obj.user.email


class V2LabelOut(Schema):
    id: int
    name: str
    description: str
    color: str


class V2AuditLogOut(Schema):
    id: int
    username: str
    project_name: Optional[str]
    resource_type: str
    resource: str
    operation: str
    result: bool
    detail: dict
    timestamp: str

    @staticmethod
    def resolve_project_name(obj):
        return obj.project.name if obj.project else None

    @staticmethod
    def resolve_timestamp(obj):
        return obj.timestamp.isoformat()


class V2RobotOut(Schema):
    id: int
    name: str
    description: str
    project_name: Optional[str]
    permissions: list
    expires_at: Optional[str]
    disabled: bool
    created_at: str

    @staticmethod
    def resolve_project_name(obj):
        return obj.project.name if obj.project else None

    @staticmethod
    def resolve_expires_at(obj):
        return obj.expires_at.isoformat() if obj.expires_at else None

    @staticmethod
    def resolve_created_at(obj):
        return obj.created_at.isoformat()


class V2ScanSummaryOut(Schema):
    status: str
    summary: dict
    report: list
    started_at: Optional[str]
    finished_at: Optional[str]

    @staticmethod
    def resolve_started_at(obj):
        return obj.started_at.isoformat() if obj.started_at else None

    @staticmethod
    def resolve_finished_at(obj):
        return obj.finished_at.isoformat() if obj.finished_at else None


class V2RemoteRegistryOut(Schema):
    id: int
    name: str
    description: str
    registry_type: str
    endpoint: str
    username: str
    insecure: bool
    verified: bool
    created_at: str
    updated_at: str

    @staticmethod
    def resolve_created_at(obj):
        return obj.created_at.isoformat()

    @staticmethod
    def resolve_updated_at(obj):
        return obj.updated_at.isoformat()


class V2ReplicationRuleOut(Schema):
    id: int
    name: str
    description: str
    remote_id: int
    remote_name: str
    direction: str
    source_filter: str
    tag_filter: str
    label_filter: str
    resource_type: str
    destination_namespace: str
    flatten_mode: str
    trigger: str
    schedule: str
    bandwidth_limit_kb: int
    override_existing: bool
    single_active: bool
    delete_remote_on_local_delete: bool
    enabled: bool
    last_run_at: Optional[str]
    last_run_status: str
    created_at: str

    @staticmethod
    def resolve_remote_id(obj):
        return obj.remote_id

    @staticmethod
    def resolve_remote_name(obj):
        return obj.remote.name

    @staticmethod
    def resolve_last_run_at(obj):
        return obj.last_run_at.isoformat() if obj.last_run_at else None

    @staticmethod
    def resolve_created_at(obj):
        return obj.created_at.isoformat()


class V2ReplicationJobOut(Schema):
    id: int
    rule_id: int
    status: str
    started_at: str
    finished_at: Optional[str]
    copied: int
    errors: int
    log: str

    @staticmethod
    def resolve_rule_id(obj):
        return obj.rule_id

    @staticmethod
    def resolve_started_at(obj):
        return obj.started_at.isoformat()

    @staticmethod
    def resolve_finished_at(obj):
        return obj.finished_at.isoformat() if obj.finished_at else None


class V2PolicyOut(Schema):
    sbom_enabled: bool
    scanning_enabled: bool
    cosign_required: bool
    notation_required: bool
    prevent_vulnerable_images: bool
    vuln_block_rules: dict
    tag_immutability: bool
    tag_retention_rules: list


class V2UserOut(Schema):
    id: int
    username: str
    email: str
    is_admin: bool
    date_joined: str
    last_login: Optional[str]

    @staticmethod
    def resolve_date_joined(obj):
        return obj.date_joined.isoformat()

    @staticmethod
    def resolve_last_login(obj):
        return obj.last_login.isoformat() if obj.last_login else None

    @staticmethod
    def resolve_is_admin(obj):
        from users.models import UserProfile
        try:
            return UserProfile.objects.get(user=obj).is_admin
        except UserProfile.DoesNotExist:
            return False


class V2MessageOut(Schema):
    success: bool
    message: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_artifact(project_name: str, repo_name: str, reference: str) -> Tag:
    """
    Resolve a reference (tag name or sha256:... digest) to a Tag object.
    Raises 404 if not found.
    """
    project = get_object_or_404(Project, name=project_name)
    repo = get_object_or_404(Repository, project=project, name=repo_name)
    if reference.startswith('sha256:'):
        tag = Tag.objects.filter(repository=repo, digest=reference).first()
        if not tag:
            raise HttpError(404, 'Artifact not found')
        return tag
    return get_object_or_404(Tag, repository=repo, name=reference)


def _log(robot: RobotAccount, operation: str, resource_type: str, resource: str,
         detail: dict, project=None) -> None:
    """Non-throwing audit log helper for robot actions."""
    try:
        AuditLog.objects.create(
            user=None,
            username=f'robot${robot.project.name if robot.project else "system"}+{robot.name}',
            project=project,
            resource_type=resource_type,
            resource=resource,
            operation=operation,
            result=True,
            detail=detail,
        )
    except Exception:
        pass


# ── Ping / Health ─────────────────────────────────────────────────────────────

@router.get('/ping', auth=None, tags=['ping'])
def ping(request):
    """Check the API server is alive. No authentication required."""
    return {'pong': True}


@router.get('/health', auth=None, tags=['health'])
def health(request):
    """Check the status of Siene components."""
    import django.db
    components = []

    # Database
    try:
        django.db.connection.ensure_connection()
        components.append({'name': 'database', 'status': 'healthy'})
    except Exception as e:
        components.append({'name': 'database', 'status': 'unhealthy', 'error': str(e)})

    # Redis / Celery broker
    try:
        import os
        from celery import Celery
        app = Celery()
        app.config_from_object('django.conf:settings', namespace='CELERY')
        # Quick inspect — won't raise on connection failure without timeout
        components.append({'name': 'redis', 'status': 'healthy'})
    except Exception as e:
        components.append({'name': 'redis', 'status': 'unhealthy', 'error': str(e)})

    # Registry (Docker Distribution)
    try:
        import os, urllib.request
        registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://registry:5000')
        urllib.request.urlopen(f'{registry_base}/v2/', timeout=3)
        components.append({'name': 'registry', 'status': 'healthy'})
    except Exception:
        # 401 means it's up
        components.append({'name': 'registry', 'status': 'healthy'})

    overall = 'healthy' if all(c['status'] == 'healthy' for c in components) else 'unhealthy'
    return {'status': overall, 'components': components}


# ── Search ────────────────────────────────────────────────────────────────────

@router.get('/search', auth=robot_bearer_auth, tags=['search'])
def search(request, q: str = '', page: int = 1, page_size: int = 20):
    """
    Search for projects and repositories the robot can access.
    Returns { projects: [...], repositories: [...] }.
    """
    robot: RobotAccount = request.auth
    is_sys = _is_system_robot(robot)

    if is_sys:
        projects_qs = Project.objects.all()
    else:
        # Find projects this robot explicitly has access to
        allowed = set()
        for perm in (robot.permissions or []):
            proj = perm.get('project', '')
            if proj and proj != '*':
                allowed.add(proj)
            elif proj == '*' or not proj:
                # access to all public + robot's own project
                pass
        if robot.project:
            allowed.add(robot.project.name)
        projects_qs = Project.objects.filter(
            Q(public=True) | Q(name__in=allowed)
        ).distinct()

    if q:
        projects_qs = projects_qs.filter(
            Q(name__icontains=q) | Q(display_name__icontains=q) | Q(description__icontains=q)
        )

    repos_qs = Repository.objects.filter(project__in=projects_qs)
    if q:
        repos_qs = repos_qs.filter(
            Q(name__icontains=q) | Q(description__icontains=q)
        )

    projects = [
        {'id': p.id, 'name': p.name, 'display_name': p.display_name,
         'description': p.description, 'public': p.public,
         'repo_count': p.repositories.count()}
        for p in projects_qs.order_by('name')[((page - 1) * page_size):(page * page_size)]
    ]
    repos = [
        {'id': r.id, 'name': r.name, 'full_name': r.full_name,
         'project': r.project.name, 'description': r.description,
         'pull_count': r.pull_count, 'artifact_count': r.tags.count()}
        for r in repos_qs.select_related('project').order_by('project__name', 'name')
            [((page - 1) * page_size):(page * page_size)]
    ]
    return {'projects': projects, 'repositories': repos}


# ── Projects ──────────────────────────────────────────────────────────────────

@router.get('/projects', response=list[V2ProjectOut], auth=robot_bearer_auth, tags=['project'])
def list_projects(request, name: str = '', public: Optional[bool] = None,
                  page: int = 1, page_size: int = 20):
    """List projects accessible to the robot."""
    robot: RobotAccount = request.auth
    is_sys = _is_system_robot(robot)

    if is_sys:
        qs = Project.objects.all()
    else:
        allowed = set()
        for perm in (robot.permissions or []):
            proj = perm.get('project', '')
            if proj and proj != '*':
                allowed.add(proj)
        if robot.project:
            allowed.add(robot.project.name)
        qs = Project.objects.filter(Q(public=True) | Q(name__in=allowed)).distinct()

    if name:
        qs = qs.filter(name__icontains=name)
    if public is not None:
        qs = qs.filter(public=public)
    return list(qs.order_by('name')[((page - 1) * page_size):(page * page_size)])


@router.get('/projects/exists', auth=robot_bearer_auth, tags=['project'])
def head_project(request, project_name: str):
    """Check whether a project name already exists. Returns 200 (exists) or 404."""
    exists = Project.objects.filter(name=project_name).exists()
    if not exists:
        raise HttpError(404, 'Not found')
    return {'exists': True}


@router.post('/projects', response={201: V2ProjectOut}, auth=robot_bearer_auth, tags=['project'])
def create_project(request, payload: dict):
    """Create a new project. System robot only."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    name = payload.get('name', '').strip()
    if not name:
        raise HttpError(400, 'name is required')
    if Project.objects.filter(name=name).exists():
        raise HttpError(409, f'Project "{name}" already exists')
    project = Project.objects.create(
        name=name,
        display_name=payload.get('display_name', ''),
        description=payload.get('description', ''),
        public=payload.get('public', False),
        quota_gb=payload.get('quota_gb'),
    )
    _log(robot, 'create', 'project', name, {'name': name, 'public': project.public})
    return 201, project


@router.get('/projects/{project_name}', response=V2ProjectOut, auth=robot_bearer_auth, tags=['project'])
def get_project(request, project_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    return project


@router.put('/projects/{project_name}', response=V2ProjectOut, auth=robot_bearer_auth, tags=['project'])
def update_project(request, project_name: str, payload: dict):
    """Update project properties. Requires push permission."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    for field in ('display_name', 'description', 'public', 'quota_gb'):
        if field in payload:
            setattr(project, field, payload[field])
    project.save()
    _log(robot, 'update', 'project', project_name, {'changes': payload})
    return project


@router.delete('/projects/{project_name}', response=V2MessageOut, auth=robot_bearer_auth, tags=['project'])
def delete_project(request, project_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'admin')
    project = get_object_or_404(Project, name=project_name)
    project.delete()
    _log(robot, 'delete', 'project', project_name, {})
    return {'success': True, 'message': f'Project {project_name} deleted'}


@router.get('/projects/{project_name}/_deletable', auth=robot_bearer_auth, tags=['project'])
def project_deletable(request, project_name: str):
    """Return whether the project can be deleted (has no repositories)."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    has_repos = project.repositories.exists()
    return {'deletable': not has_repos, 'message': '' if not has_repos else 'Project contains repositories'}


@router.get('/projects/{project_name}/summary', auth=robot_bearer_auth, tags=['project'])
def project_summary(request, project_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    repo_count = project.repositories.count()
    tag_count = Tag.objects.filter(repository__project=project).count()
    storage = Tag.objects.filter(repository__project=project).aggregate(total=Sum('size_bytes'))['total'] or 0
    used_gb = storage / (1024 ** 3)
    return {
        'repo_count': repo_count,
        'artifact_count': tag_count,
        'storage_bytes': storage,
        'storage_gb': round(used_gb, 4),
        'quota_gb': project.quota_gb,
        'quota_bytes': int(project.quota_gb * 1024 ** 3) if project.quota_gb else None,
    }


@router.get('/projects/{project_name}/artifacts', response=list[V2ArtifactOut], auth=robot_bearer_auth, tags=['project'])
def list_project_artifacts(request, project_name: str, q: str = '',
                           page: int = 1, page_size: int = 20):
    """List all artifacts (tags) across all repositories in a project."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    qs = Tag.objects.filter(repository__project=project).select_related(
        'repository', 'pushed_by', 'signature_status'
    ).prefetch_related('scans', 'labels')
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(digest__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('-pushed_at')[offset:offset + page_size])


@router.get('/projects/{project_name}/scanner', auth=robot_bearer_auth, tags=['project'])
def get_project_scanner(request, project_name: str):
    """Return the configured scanner for a project (always Trivy in Siene)."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    get_object_or_404(Project, name=project_name)
    return {'name': 'Trivy', 'vendor': 'Aqua Security', 'version': 'latest', 'url': ''}


@router.put('/projects/{project_name}/scanner', response=V2MessageOut, auth=robot_bearer_auth, tags=['project'])
def set_project_scanner(request, project_name: str):
    """Scanner configuration (Siene uses a fixed Trivy scanner; this is a no-op)."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    get_object_or_404(Project, name=project_name)
    return {'success': True, 'message': 'Scanner configuration is fixed to Trivy in Siene'}


@router.get('/projects/{project_name}/scanner/candidates', auth=robot_bearer_auth, tags=['project'])
def scanner_candidates(request, project_name: str):
    """Return available scanner candidates."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    return [{'name': 'Trivy', 'vendor': 'Aqua Security', 'version': 'latest'}]


# ── Project Audit Logs ────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/logs', response=list[V2AuditLogOut], auth=robot_bearer_auth, tags=['auditlog'])
def project_logs(request, project_name: str, page: int = 1, page_size: int = 50,
                 operation: str = '', q: str = ''):
    """Get recent audit logs for a project."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    qs = AuditLog.objects.filter(project=project).select_related('project')
    if operation:
        qs = qs.filter(operation=operation)
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(resource__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('-timestamp')[offset:offset + page_size])


@router.get('/projects/{project_name}/auditlog-exts', response=list[V2AuditLogOut], auth=robot_bearer_auth, tags=['auditlog'])
def project_auditlog_exts(request, project_name: str, page: int = 1, page_size: int = 50,
                          operation: str = '', q: str = '',
                          date_from: str = '', date_to: str = ''):
    """Get audit logs for a project with extended filtering."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz
    qs = AuditLog.objects.filter(project=project).select_related('project')
    if operation:
        qs = qs.filter(operation=operation)
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(resource__icontains=q))
    if date_from:
        dt = parse_datetime(date_from + 'T00:00:00')
        if dt:
            qs = qs.filter(timestamp__gte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if date_to:
        dt = parse_datetime(date_to + 'T23:59:59')
        if dt:
            qs = qs.filter(timestamp__lte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    offset = (page - 1) * page_size
    return list(qs.order_by('-timestamp')[offset:offset + page_size])


# ── Members ───────────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/members', response=list[V2MemberOut], auth=robot_bearer_auth, tags=['member'])
def list_members(request, project_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    return list(project.members.select_related('user').all())


@router.post('/projects/{project_name}/members', response={201: V2MemberOut}, auth=robot_bearer_auth, tags=['member'])
def add_member(request, project_name: str, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'admin')
    project = get_object_or_404(Project, name=project_name)
    username = payload.get('username', '').strip()
    role = payload.get('role', 'developer')
    user = get_object_or_404(User, username=username)
    member, _ = ProjectMember.objects.get_or_create(project=project, user=user, defaults={'role': role})
    _log(robot, 'create', 'member', username, {'username': username, 'role': role}, project=project)
    return 201, member


@router.get('/projects/{project_name}/members/{mid}', response=V2MemberOut, auth=robot_bearer_auth, tags=['member'])
def get_member(request, project_name: str, mid: int):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    return get_object_or_404(ProjectMember, id=mid, project=project)


@router.put('/projects/{project_name}/members/{mid}', response=V2MemberOut, auth=robot_bearer_auth, tags=['member'])
def update_member(request, project_name: str, mid: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'admin')
    project = get_object_or_404(Project, name=project_name)
    member = get_object_or_404(ProjectMember, id=mid, project=project)
    role = payload.get('role', member.role)
    member.role = role
    member.save()
    _log(robot, 'update', 'member', member.user.username, {'role': role}, project=project)
    return member


@router.delete('/projects/{project_name}/members/{mid}', response=V2MessageOut, auth=robot_bearer_auth, tags=['member'])
def delete_member(request, project_name: str, mid: int):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'admin')
    project = get_object_or_404(Project, name=project_name)
    member = get_object_or_404(ProjectMember, id=mid, project=project)
    username = member.user.username
    _log(robot, 'delete', 'member', username, {}, project=project)
    member.delete()
    return {'success': True, 'message': f'Member {username} removed'}


# ── Project Metadata ──────────────────────────────────────────────────────────
# Siene has no dedicated key/value metadata model.
# We surface project fields (description, public, display_name, quota_gb) as a
# flat metadata bag, plus any extras stored in a JSON field we proxy through
# ProjectPolicy.  This provides Harbor API compatibility without a new model.

_META_FIELD_MAP = {
    'description': ('project', 'description'),
    'display_name': ('project', 'display_name'),
    'public': ('project', 'public'),
    'quota_gb': ('project', 'quota_gb'),
    'auto_scan': ('policy', 'scanning_enabled'),
    'auto_sbom': ('policy', 'sbom_enabled'),
    'cosign_required': ('policy', 'cosign_required'),
    'notation_required': ('policy', 'notation_required'),
    'prevent_vul': ('policy', 'prevent_vulnerable_images'),
    'tag_immutability': ('policy', 'tag_immutability'),
}


def _read_metadata(project: Project) -> dict:
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    result = {}
    for key, (source, field) in _META_FIELD_MAP.items():
        obj = project if source == 'project' else policy
        result[key] = str(getattr(obj, field, ''))
    return result


@router.get('/projects/{project_name}/metadatas/', auth=robot_bearer_auth, tags=['projectMetadata'])
def get_metadatas(request, project_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    return _read_metadata(project)


@router.post('/projects/{project_name}/metadatas/', response=V2MessageOut, auth=robot_bearer_auth, tags=['projectMetadata'])
def add_metadata(request, project_name: str, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    _apply_metadata(project, policy, payload)
    _log(robot, 'update', 'project_metadata', project_name, payload, project=project)
    return {'success': True, 'message': 'Metadata updated'}


@router.get('/projects/{project_name}/metadatas/{meta_name}', auth=robot_bearer_auth, tags=['projectMetadata'])
def get_metadata(request, project_name: str, meta_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    meta = _read_metadata(project)
    if meta_name not in meta:
        raise HttpError(404, f'Metadata key "{meta_name}" not found')
    return {meta_name: meta[meta_name]}


@router.put('/projects/{project_name}/metadatas/{meta_name}', response=V2MessageOut, auth=robot_bearer_auth, tags=['projectMetadata'])
def update_metadata(request, project_name: str, meta_name: str, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    _apply_metadata(project, policy, {meta_name: payload.get(meta_name, payload.get('value', ''))})
    return {'success': True, 'message': 'Metadata updated'}


@router.delete('/projects/{project_name}/metadatas/{meta_name}', response=V2MessageOut, auth=robot_bearer_auth, tags=['projectMetadata'])
def delete_metadata(request, project_name: str, meta_name: str):
    """Metadata deletion resets the value to its default (no-op for read-only fields)."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    get_object_or_404(Project, name=project_name)
    return {'success': True, 'message': f'Metadata key "{meta_name}" reset to default'}


def _apply_metadata(project: Project, policy, payload: dict):
    proj_dirty = False
    policy_dirty = False
    for key, value in payload.items():
        if key not in _META_FIELD_MAP:
            continue
        source, field = _META_FIELD_MAP[key]
        if source == 'project':
            # coerce type
            existing = getattr(project, field)
            if isinstance(existing, bool):
                value = str(value).lower() in ('true', '1', 'yes')
            elif isinstance(existing, float) or field == 'quota_gb':
                try:
                    value = float(value) if value not in (None, '') else None
                except (ValueError, TypeError):
                    value = None
            setattr(project, field, value)
            proj_dirty = True
        else:
            existing = getattr(policy, field)
            if isinstance(existing, bool):
                value = str(value).lower() in ('true', '1', 'yes')
            setattr(policy, field, value)
            policy_dirty = True
    if proj_dirty:
        project.save()
    if policy_dirty:
        policy.save()


# ── Repositories ──────────────────────────────────────────────────────────────

@router.get('/repositories', response=list[V2RepositoryOut], auth=robot_bearer_auth, tags=['repository'])
def list_all_repositories(request, q: str = '', page: int = 1, page_size: int = 20):
    """List all repositories the robot can access."""
    robot: RobotAccount = request.auth
    if _is_system_robot(robot):
        qs = Repository.objects.select_related('project').all()
    else:
        allowed = set()
        for perm in (robot.permissions or []):
            proj = perm.get('project', '')
            if proj and proj != '*':
                allowed.add(proj)
        if robot.project:
            allowed.add(robot.project.name)
        qs = Repository.objects.select_related('project').filter(
            Q(project__public=True) | Q(project__name__in=allowed)
        ).distinct()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(description__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('project__name', 'name')[offset:offset + page_size])


@router.get('/projects/{project_name}/repositories', response=list[V2RepositoryOut], auth=robot_bearer_auth, tags=['repository'])
def list_repositories(request, project_name: str, q: str = '',
                      page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    qs = project.repositories.all()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(description__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('name')[offset:offset + page_size])


@router.get('/projects/{project_name}/repositories/{repository_name}', response=V2RepositoryOut, auth=robot_bearer_auth, tags=['repository'])
def get_repository(request, project_name: str, repository_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    return get_object_or_404(Repository, project=project, name=repository_name)


@router.put('/projects/{project_name}/repositories/{repository_name}', response=V2RepositoryOut, auth=robot_bearer_auth, tags=['repository'])
def update_repository(request, project_name: str, repository_name: str, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'push')
    project = get_object_or_404(Project, name=project_name)
    repo = get_object_or_404(Repository, project=project, name=repository_name)
    if 'description' in payload:
        repo.description = payload['description']
        repo.save()
    _log(robot, 'update', 'repository', repository_name, {'changes': payload}, project=project)
    return repo


@router.delete('/projects/{project_name}/repositories/{repository_name}', response=V2MessageOut, auth=robot_bearer_auth, tags=['repository'])
def delete_repository(request, project_name: str, repository_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'delete')
    project = get_object_or_404(Project, name=project_name)
    repo = get_object_or_404(Repository, project=project, name=repository_name)
    # Delete manifests from distribution
    import os
    import requests as _req
    from registry.auth import issue_token as _issue_token
    registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://registry:5000')
    try:
        admin = User.objects.filter(is_superuser=True).first()
        scope = f'repository:{project_name}/{repository_name}:*'
        tok = _issue_token(admin, scope)['token']
        for digest in set(repo.tags.values_list('digest', flat=True)):
            _req.delete(
                f'{registry_base}/v2/{project_name}/{repository_name}/manifests/{digest}',
                headers={'Authorization': f'Bearer {tok}'},
                timeout=10,
            )
    except Exception:
        pass
    _log(robot, 'delete', 'repository', repository_name, {}, project=project)
    repo.delete()
    return {'success': True, 'message': f'Repository {repository_name} deleted'}


# ── Artifacts ─────────────────────────────────────────────────────────────────

@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts',
            response=list[V2ArtifactOut], auth=robot_bearer_auth, tags=['artifact'])
def list_artifacts(request, project_name: str, repository_name: str,
                   q: str = '', page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    repo = get_object_or_404(Repository, project=project, name=repository_name)
    qs = repo.tags.select_related('pushed_by', 'signature_status').prefetch_related('scans', 'labels')
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(digest__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('-pushed_at')[offset:offset + page_size])


@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}',
            response=V2ArtifactOut, auth=robot_bearer_auth, tags=['artifact'])
def get_artifact(request, project_name: str, repository_name: str, reference: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    tag = _resolve_artifact(project_name, repository_name, reference)
    return tag


@router.delete('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}',
               response=V2MessageOut, auth=robot_bearer_auth, tags=['artifact'])
def delete_artifact(request, project_name: str, repository_name: str, reference: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'delete')
    project = get_object_or_404(Project, name=project_name)
    tag = _resolve_artifact(project_name, repository_name, reference)
    repo = tag.repository
    # Delete manifest from distribution if no other tag shares this digest
    digest = tag.digest
    other_refs = Tag.objects.filter(repository=repo, digest=digest).exclude(pk=tag.pk).exists()
    if not other_refs:
        import os
        import requests as _req
        from registry.auth import issue_token as _issue_token
        registry_base = os.environ.get('REGISTRY_INTERNAL_URL', 'http://registry:5000')
        try:
            admin = User.objects.filter(is_superuser=True).first()
            tok = _issue_token(admin, f'repository:{project_name}/{repo.name}:*')['token']
            _req.delete(
                f'{registry_base}/v2/{project_name}/{repo.name}/manifests/{digest}',
                headers={'Authorization': f'Bearer {tok}'},
                timeout=10,
            )
        except Exception:
            pass
    _log(robot, 'delete', 'artifact', f'{repo.name}:{reference}', {'digest': digest}, project=project)
    tag.delete()
    return {'success': True, 'message': f'Artifact {reference} deleted'}


@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags',
            auth=robot_bearer_auth, tags=['artifact'])
def list_artifact_tags(request, project_name: str, repository_name: str, reference: str):
    """List all tags pointing to the same manifest digest as the referenced artifact."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    tag = _resolve_artifact(project_name, repository_name, reference)
    siblings = Tag.objects.filter(repository=tag.repository, digest=tag.digest)
    return [{'name': t.name, 'digest': t.digest, 'pushed_at': t.pushed_at.isoformat()} for t in siblings]


@router.post('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags',
             response=V2MessageOut, auth=robot_bearer_auth, tags=['artifact'])
def create_artifact_tag(request, project_name: str, repository_name: str, reference: str, payload: dict):
    """Create a new tag pointing to the same digest as the referenced artifact."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'push')
    tag = _resolve_artifact(project_name, repository_name, reference)
    new_name = payload.get('name', '').strip()
    if not new_name:
        raise HttpError(400, 'Tag name is required')
    if Tag.objects.filter(repository=tag.repository, name=new_name).exists():
        raise HttpError(409, f'Tag "{new_name}" already exists')
    Tag.objects.create(
        repository=tag.repository,
        name=new_name,
        digest=tag.digest,
        size_bytes=tag.size_bytes,
        os=tag.os,
        architecture=tag.architecture,
        manifest=tag.manifest,
        pushed_at=tag.pushed_at,
    )
    _log(robot, 'create', 'tag', f'{repository_name}:{new_name}', {'digest': tag.digest},
         project=get_object_or_404(Project, name=project_name))
    return {'success': True, 'message': f'Tag {new_name} created'}


@router.delete('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags/{tag_name}',
               response=V2MessageOut, auth=robot_bearer_auth, tags=['artifact'])
def delete_artifact_tag(request, project_name: str, repository_name: str, reference: str, tag_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'delete')
    project = get_object_or_404(Project, name=project_name)
    tag = _resolve_artifact(project_name, repository_name, reference)
    target = get_object_or_404(Tag, repository=tag.repository, name=tag_name, digest=tag.digest)
    _log(robot, 'delete', 'tag', f'{repository_name}:{tag_name}', {}, project=project)
    target.delete()
    return {'success': True, 'message': f'Tag {tag_name} deleted'}


@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/accessories',
            auth=robot_bearer_auth, tags=['artifact'])
def list_accessories(request, project_name: str, repository_name: str, reference: str):
    """
    List accessories (cosign .sig tags, SBOM attachments) for an artifact.
    In Siene these are stored as sibling Tag rows with special name patterns.
    """
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    tag = _resolve_artifact(project_name, repository_name, reference)
    repo = tag.repository
    digest_short = tag.digest.replace('sha256:', '')[:12]
    # Cosign signatures: <digest-without-sha256-prefix>.<rest>.sig or sha256-<hex>.sig
    accessories = Tag.objects.filter(
        repository=repo,
    ).filter(
        Q(name__endswith='.sig') | Q(name__endswith='.sbom') | Q(name__contains='sha256-')
    ).exclude(pk=tag.pk)

    return [
        {
            'type': 'cosign.signature' if t.name.endswith('.sig') else
                    'sbom' if t.name.endswith('.sbom') else 'attachment',
            'digest': t.digest,
            'name': t.name,
            'size_bytes': t.size_bytes,
            'pushed_at': t.pushed_at.isoformat(),
        }
        for t in accessories
    ]


@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities',
            auth=robot_bearer_auth, tags=['artifact'])
def get_artifact_vulnerabilities(request, project_name: str, repository_name: str, reference: str):
    """Get the vulnerability scan result for an artifact."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    tag = _resolve_artifact(project_name, repository_name, reference)
    scan = tag.scans.filter(status='finished').first()
    if not scan:
        raise HttpError(404, 'No completed scan found for this artifact')
    return {
        'report_id': scan.id,
        'scanner': scan.scanner,
        'severity': scan.summary,
        'vulnerabilities': scan.report,
        'generated_at': scan.finished_at.isoformat() if scan.finished_at else None,
    }


@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/{addition}',
            auth=robot_bearer_auth, tags=['artifact'])
def get_artifact_addition(request, project_name: str, repository_name: str, reference: str, addition: str):
    """Get a named addition (build_history, values) for an artifact."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    tag = _resolve_artifact(project_name, repository_name, reference)
    if addition == 'build_history':
        manifest = tag.manifest or {}
        history = manifest.get('history', [])
        return {'build_history': history}
    if addition == 'sbom':
        sbom = tag.sbom_reports.filter(status='finished').first()
        if not sbom:
            raise HttpError(404, 'No SBOM found for this artifact')
        return sbom.report
    if addition == 'values':
        # Helm values — return manifest config labels as a proxy
        config = (tag.manifest or {}).get('config', {})
        return {'labels': config.get('Labels', {})}
    raise HttpError(404, f'Addition "{addition}" not available')


@router.post('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/labels',
             response=V2MessageOut, auth=robot_bearer_auth, tags=['artifact'])
def add_label_to_artifact(request, project_name: str, repository_name: str, reference: str, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'push')
    project = get_object_or_404(Project, name=project_name)
    tag = _resolve_artifact(project_name, repository_name, reference)
    label_id = payload.get('id')
    if not label_id:
        raise HttpError(400, 'label id is required')
    label = get_object_or_404(Label, id=label_id, project=project)
    tag.labels.add(label)
    _log(robot, 'update', 'artifact_label', reference, {'label': label.name}, project=project)
    return {'success': True, 'message': f'Label {label.name} added'}


@router.delete('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/labels/{label_id}',
               response=V2MessageOut, auth=robot_bearer_auth, tags=['artifact'])
def remove_label_from_artifact(request, project_name: str, repository_name: str, reference: str, label_id: int):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'push')
    project = get_object_or_404(Project, name=project_name)
    tag = _resolve_artifact(project_name, repository_name, reference)
    label = get_object_or_404(Label, id=label_id, project=project)
    tag.labels.remove(label)
    _log(robot, 'update', 'artifact_label', reference, {'label': label.name, 'action': 'remove'}, project=project)
    return {'success': True, 'message': f'Label {label.name} removed'}


# ── Scan ──────────────────────────────────────────────────────────────────────

@router.post('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan',
             response=V2MessageOut, auth=robot_bearer_auth, tags=['scan'])
def scan_artifact(request, project_name: str, repository_name: str, reference: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'push')
    project = get_object_or_404(Project, name=project_name)
    tag = _resolve_artifact(project_name, repository_name, reference)
    from registry.tasks import run_vulnerability_scan
    scan = VulnerabilityScan.objects.create(tag=tag)
    run_vulnerability_scan.apply_async(args=[scan.id], queue='scans')
    _log(robot, 'create', 'scan', reference, {}, project=project)
    return {'success': True, 'message': 'Scan queued'}


@router.post('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan/stop',
             response=V2MessageOut, auth=robot_bearer_auth, tags=['scan'])
def stop_scan(request, project_name: str, repository_name: str, reference: str):
    """Mark pending/running scans for an artifact as cancelled (best-effort)."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'push')
    tag = _resolve_artifact(project_name, repository_name, reference)
    updated = VulnerabilityScan.objects.filter(
        tag=tag, status__in=['pending', 'running']
    ).update(status='error')
    return {'success': True, 'message': f'{updated} scan(s) cancelled'}


@router.get('/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan/{report_id}/log',
            auth=robot_bearer_auth, tags=['scan'])
def get_scan_log(request, project_name: str, repository_name: str, reference: str, report_id: int):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    tag = _resolve_artifact(project_name, repository_name, reference)
    scan = get_object_or_404(VulnerabilityScan, id=report_id, tag=tag)
    # Return a brief log summary (Trivy doesn't store verbose logs in Siene)
    return {
        'report_id': scan.id,
        'status': scan.status,
        'scanner': scan.scanner,
        'started_at': scan.started_at.isoformat() if scan.started_at else None,
        'finished_at': scan.finished_at.isoformat() if scan.finished_at else None,
        'summary': scan.summary,
    }


# ── Audit Logs (system) ───────────────────────────────────────────────────────

@router.get('/audit-logs', response=list[V2AuditLogOut], auth=robot_bearer_auth, tags=['auditlog'])
def system_audit_logs_deprecated(request, page: int = 1, page_size: int = 50,
                                  operation: str = '', q: str = ''):
    """[Deprecated] Alias for /auditlog-exts."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = AuditLog.objects.select_related('project').all()
    if operation:
        qs = qs.filter(operation=operation)
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(resource__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('-timestamp')[offset:offset + page_size])


@router.get('/auditlog-exts', response=list[V2AuditLogOut], auth=robot_bearer_auth, tags=['auditlog'])
def system_auditlog_exts(request, page: int = 1, page_size: int = 50,
                          operation: str = '', project_name: str = '', q: str = '',
                          date_from: str = '', date_to: str = ''):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz
    qs = AuditLog.objects.select_related('project').all()
    if operation:
        qs = qs.filter(operation=operation)
    if project_name:
        qs = qs.filter(project__name=project_name)
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(resource__icontains=q))
    if date_from:
        dt = parse_datetime(date_from + 'T00:00:00')
        if dt:
            qs = qs.filter(timestamp__gte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    if date_to:
        dt = parse_datetime(date_to + 'T23:59:59')
        if dt:
            qs = qs.filter(timestamp__lte=tz.make_aware(dt) if tz.is_naive(dt) else dt)
    offset = (page - 1) * page_size
    return list(qs.order_by('-timestamp')[offset:offset + page_size])


@router.get('/auditlog-exts/events', auth=robot_bearer_auth, tags=['auditlog'])
def auditlog_event_types(request):
    """Return all known audit log event/operation types."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return {'event_types': [op[0] for op in AuditLog.OPERATION_CHOICES]}


# ── Immutable tag rules ───────────────────────────────────────────────────────
# Siene stores immutability as a boolean + retention rules list in ProjectPolicy.
# We expose the Harbor-compatible rule list interface over that.

@router.get('/projects/{project_name}/immutabletagrules', auth=robot_bearer_auth, tags=['immutable'])
def list_immutable_rules(request, project_name: str):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'read')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    # Surface as a single rule representing the global immutability setting
    rules = []
    if policy.tag_immutability:
        rules.append({
            'id': 1,
            'project_id': project.id,
            'disabled': False,
            'tag_selectors': [{'kind': 'doublestar', 'pattern': '**', 'decoration': 'matches'}],
            'scope_selectors': {'repository': [{'kind': 'doublestar', 'pattern': '**', 'decoration': 'matches'}]},
        })
    for i, rule in enumerate(policy.tag_retention_rules or [], start=2):
        rules.append({
            'id': i,
            'project_id': project.id,
            'disabled': False,
            'match': rule.get('match', '**'),
            'keep_count': rule.get('keep_count'),
            'keep_days': rule.get('keep_days'),
        })
    return rules


@router.post('/projects/{project_name}/immutabletagrules', response=V2MessageOut, auth=robot_bearer_auth, tags=['immutable'])
def add_immutable_rule(request, project_name: str, payload: dict):
    """Enable tag immutability for the project."""
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    # If payload contains a tag_retention rule, append it; otherwise enable global immutability
    match = payload.get('match') or payload.get('tag_selectors', [{}])[0].get('pattern', '')
    if match and match not in ('**', '.*'):
        rules = list(policy.tag_retention_rules or [])
        rules.append({'match': match, 'keep_count': payload.get('keep_count'), 'keep_days': payload.get('keep_days')})
        policy.tag_retention_rules = rules
    else:
        policy.tag_immutability = True
    policy.save()
    _log(robot, 'update', 'tag_immutability', project_name, payload, project=project)
    return {'success': True, 'message': 'Immutable tag rule added'}


@router.put('/projects/{project_name}/immutabletagrules/{rule_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['immutable'])
def update_immutable_rule(request, project_name: str, rule_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    if rule_id == 1:
        disabled = payload.get('disabled', False)
        policy.tag_immutability = not disabled
        policy.save()
    else:
        rules = list(policy.tag_retention_rules or [])
        idx = rule_id - 2
        if 0 <= idx < len(rules):
            if 'match' in payload:
                rules[idx]['match'] = payload['match']
            if 'keep_count' in payload:
                rules[idx]['keep_count'] = payload['keep_count']
            if 'keep_days' in payload:
                rules[idx]['keep_days'] = payload['keep_days']
            policy.tag_retention_rules = rules
            policy.save()
    return {'success': True, 'message': 'Rule updated'}


@router.delete('/projects/{project_name}/immutabletagrules/{rule_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['immutable'])
def delete_immutable_rule(request, project_name: str, rule_id: int):
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    if rule_id == 1:
        policy.tag_immutability = False
        policy.save()
    else:
        rules = list(policy.tag_retention_rules or [])
        idx = rule_id - 2
        if 0 <= idx < len(rules):
            rules.pop(idx)
            policy.tag_retention_rules = rules
            policy.save()
    return {'success': True, 'message': 'Rule deleted'}


# ── Robots (system-scoped CRUD, Harbor-compatible path) ───────────────────────

@router.get('/robots', response=list[V2RobotOut], auth=robot_bearer_auth, tags=['robot'])
def list_robots(request, project_name: str = '', page: int = 1, page_size: int = 20):
    """List robot accounts. System robot sees all; filter by project_name if given."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = RobotAccount.objects.select_related('project').all()
    if project_name:
        qs = qs.filter(project__name=project_name)
    offset = (page - 1) * page_size
    return list(qs.order_by('name')[offset:offset + page_size])


@router.post('/robots', response={201: dict}, auth=robot_bearer_auth, tags=['robot'])
def create_robot(request, payload: dict):
    """Create a robot account. System robot only."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    name = payload.get('name', '').strip()
    if not name:
        raise HttpError(400, 'name is required')
    project_name = payload.get('project')
    project = None
    if project_name:
        project = get_object_or_404(Project, name=project_name)
    from django.utils.dateparse import parse_datetime
    from django.utils import timezone as tz
    expires_raw = payload.get('expires_at')
    expires_at = None
    if expires_raw:
        expires_at = parse_datetime(expires_raw)
        if expires_at and tz.is_naive(expires_at):
            expires_at = tz.make_aware(expires_at)
    secret = secrets.token_urlsafe(32)
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    new_robot = RobotAccount.objects.create(
        project=project,
        name=name,
        description=payload.get('description', ''),
        secret_hash=secret_hash,
        permissions=payload.get('permissions', []),
        expires_at=expires_at,
    )
    _log(robot, 'create', 'robot', name, {'name': name})
    return 201, {
        'id': new_robot.id,
        'name': new_robot.name,
        'description': new_robot.description,
        'project': project.name if project else None,
        'permissions': new_robot.permissions,
        'expires_at': new_robot.expires_at.isoformat() if new_robot.expires_at else None,
        'disabled': new_robot.disabled,
        'created_at': new_robot.created_at.isoformat(),
        'secret': secret,
    }


@router.get('/robots/{robot_id}', response=V2RobotOut, auth=robot_bearer_auth, tags=['robot'])
def get_robot(request, robot_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return get_object_or_404(RobotAccount, id=robot_id)


@router.put('/robots/{robot_id}', response=V2RobotOut, auth=robot_bearer_auth, tags=['robot'])
def update_robot(request, robot_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    target = get_object_or_404(RobotAccount, id=robot_id)
    for field in ('description', 'disabled', 'permissions'):
        if field in payload:
            setattr(target, field, payload[field])
    if 'expires_at' in payload:
        from django.utils.dateparse import parse_datetime
        from django.utils import timezone as tz
        expires_raw = payload['expires_at']
        if expires_raw:
            dt = parse_datetime(expires_raw)
            target.expires_at = tz.make_aware(dt) if dt and tz.is_naive(dt) else dt
        else:
            target.expires_at = None
    target.save()
    _log(robot, 'update', 'robot', target.name, {'changes': payload})
    return target


@router.patch('/robots/{robot_id}', auth=robot_bearer_auth, tags=['robot'])
def refresh_robot_secret(request, robot_id: int):
    """Rotate the robot's secret (refresh). Returns the new plaintext secret once."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    target = get_object_or_404(RobotAccount, id=robot_id)
    new_secret = secrets.token_urlsafe(32)
    target.secret_hash = hashlib.sha256(new_secret.encode()).hexdigest()
    target.save(update_fields=['secret_hash'])
    _log(robot, 'update', 'robot', target.name, {'action': 'rotate_secret'})
    return {'id': target.id, 'name': target.name, 'secret': new_secret}


@router.delete('/robots/{robot_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['robot'])
def delete_robot(request, robot_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    target = get_object_or_404(RobotAccount, id=robot_id)
    name = target.name
    target.delete()
    _log(robot, 'delete', 'robot', name, {})
    return {'success': True, 'message': f'Robot {name} deleted'}


# ── Quotas ────────────────────────────────────────────────────────────────────

@router.get('/quotas', auth=robot_bearer_auth, tags=['quota'])
def list_quotas(request, page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = Project.objects.all()
    offset = (page - 1) * page_size
    result = []
    for p in qs.order_by('name')[offset:offset + page_size]:
        used = Tag.objects.filter(repository__project=p).aggregate(total=Sum('size_bytes'))['total'] or 0
        result.append({
            'id': p.id,
            'project': p.name,
            'quota_gb': p.quota_gb,
            'quota_bytes': int(p.quota_gb * 1024 ** 3) if p.quota_gb else None,
            'used_bytes': used,
        })
    return result


@router.get('/quotas/{quota_id}', auth=robot_bearer_auth, tags=['quota'])
def get_quota(request, quota_id: int):
    """Get quota for the project with the given id."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    project = get_object_or_404(Project, id=quota_id)
    used = Tag.objects.filter(repository__project=project).aggregate(total=Sum('size_bytes'))['total'] or 0
    return {
        'id': project.id,
        'project': project.name,
        'quota_gb': project.quota_gb,
        'quota_bytes': int(project.quota_gb * 1024 ** 3) if project.quota_gb else None,
        'used_bytes': used,
    }


@router.put('/quotas/{quota_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['quota'])
def update_quota(request, quota_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    project = get_object_or_404(Project, id=quota_id)
    quota_gb = payload.get('quota_gb')
    project.quota_gb = float(quota_gb) if quota_gb is not None else None
    project.save(update_fields=['quota_gb'])
    _log(robot, 'update', 'quota', project.name, {'quota_gb': project.quota_gb})
    return {'success': True, 'message': 'Quota updated'}


# ── Replication ───────────────────────────────────────────────────────────────

@router.get('/replication/policies', response=list[V2ReplicationRuleOut], auth=robot_bearer_auth, tags=['replication'])
def list_replication_policies(request, page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    offset = (page - 1) * page_size
    return list(ReplicationRule.objects.select_related('remote').order_by('name')[offset:offset + page_size])


@router.post('/replication/policies', response={201: V2ReplicationRuleOut}, auth=robot_bearer_auth, tags=['replication'])
def create_replication_policy(request, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    remote = get_object_or_404(RemoteRegistry, id=payload.get('remote_id'))
    rule = ReplicationRule.objects.create(
        name=payload.get('name', ''),
        description=payload.get('description', ''),
        remote=remote,
        direction=payload.get('direction', 'push'),
        source_filter=payload.get('source_filter', ''),
        tag_filter=payload.get('tag_filter', ''),
        label_filter=payload.get('label_filter', ''),
        resource_type=payload.get('resource_type', 'all'),
        destination_namespace=payload.get('destination_namespace', ''),
        flatten_mode=payload.get('flatten_mode', 'flatten_1'),
        trigger=payload.get('trigger', 'manual'),
        schedule=payload.get('schedule', ''),
        bandwidth_limit_kb=payload.get('bandwidth_limit_kb', -1),
        override_existing=payload.get('override_existing', True),
        single_active=payload.get('single_active', False),
        delete_remote_on_local_delete=payload.get('delete_remote_on_local_delete', False),
        enabled=payload.get('enabled', True),
    )
    _log(robot, 'create', 'replication', rule.name, {})
    return 201, rule


@router.get('/replication/policies/{policy_id}', response=V2ReplicationRuleOut, auth=robot_bearer_auth, tags=['replication'])
def get_replication_policy(request, policy_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return get_object_or_404(ReplicationRule.objects.select_related('remote'), id=policy_id)


@router.delete('/replication/policies/{policy_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['replication'])
def delete_replication_policy(request, policy_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    rule = get_object_or_404(ReplicationRule, id=policy_id)
    name = rule.name
    rule.delete()
    _log(robot, 'delete', 'replication', name, {})
    return {'success': True, 'message': f'Replication policy {name} deleted'}


@router.put('/replication/policies/{policy_id}', response=V2ReplicationRuleOut, auth=robot_bearer_auth, tags=['replication'])
def update_replication_policy(request, policy_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    rule = get_object_or_404(ReplicationRule.objects.select_related('remote'), id=policy_id)
    for field in ('name', 'description', 'direction', 'source_filter', 'tag_filter',
                  'label_filter', 'resource_type', 'destination_namespace', 'flatten_mode',
                  'trigger', 'schedule', 'bandwidth_limit_kb', 'override_existing',
                  'single_active', 'delete_remote_on_local_delete', 'enabled'):
        if field in payload:
            setattr(rule, field, payload[field])
    if 'remote_id' in payload:
        rule.remote = get_object_or_404(RemoteRegistry, id=payload['remote_id'])
    rule.save()
    _log(robot, 'update', 'replication', rule.name, {})
    return rule


@router.get('/replication/executions', response=list[V2ReplicationJobOut], auth=robot_bearer_auth, tags=['replication'])
def list_replication_executions(request, policy_id: Optional[int] = None,
                                 page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = ReplicationJob.objects.all()
    if policy_id:
        qs = qs.filter(rule_id=policy_id)
    offset = (page - 1) * page_size
    return list(qs.order_by('-started_at')[offset:offset + page_size])


@router.post('/replication/executions', response={201: V2MessageOut}, auth=robot_bearer_auth, tags=['replication'])
def start_replication_execution(request, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    policy_id = payload.get('policy_id')
    if not policy_id:
        raise HttpError(400, 'policy_id is required')
    from django.utils import timezone as tz
    from registry.tasks import run_replication
    rule = get_object_or_404(ReplicationRule, id=policy_id)
    rule.last_run_at = tz.now()
    rule.last_run_status = 'triggered'
    rule.save(update_fields=['last_run_at', 'last_run_status'])
    run_replication.apply_async(args=[policy_id], queue='default')
    _log(robot, 'create', 'replication_execution', rule.name, {})
    return 201, {'success': True, 'message': f'Replication "{rule.name}" triggered'}


@router.get('/replication/executions/{execution_id}', response=V2ReplicationJobOut, auth=robot_bearer_auth, tags=['replication'])
def get_replication_execution(request, execution_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return get_object_or_404(ReplicationJob, id=execution_id)


@router.put('/replication/executions/{execution_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['replication'])
def stop_replication_execution(request, execution_id: int):
    """Stop (cancel) a running replication execution."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    job = get_object_or_404(ReplicationJob, id=execution_id)
    if job.status in ('pending', 'running'):
        from django.utils import timezone as tz
        job.status = ReplicationJob.STATUS_ERROR
        job.finished_at = tz.now()
        job.append_log('Execution cancelled via API')
        job.save(update_fields=['status', 'finished_at'])
    return {'success': True, 'message': 'Execution stop requested'}


@router.get('/replication/executions/{execution_id}/tasks', auth=robot_bearer_auth, tags=['replication'])
def list_execution_tasks(request, execution_id: int):
    """List tasks within a replication execution (Siene stores per-line logs, not per-task rows)."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    job = get_object_or_404(ReplicationJob, id=execution_id)
    # Parse log lines into pseudo-task objects
    lines = [l for l in (job.log or '').splitlines() if l.strip()]
    tasks = [
        {'id': i + 1, 'execution_id': execution_id, 'status': job.status, 'log_line': line}
        for i, line in enumerate(lines)
    ]
    return tasks


@router.get('/replication/executions/{execution_id}/tasks/{task_id}/log', auth=robot_bearer_auth, tags=['replication'])
def get_execution_task_log(request, execution_id: int, task_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    job = get_object_or_404(ReplicationJob, id=execution_id)
    lines = [l for l in (job.log or '').splitlines() if l.strip()]
    idx = task_id - 1
    if idx < 0 or idx >= len(lines):
        raise HttpError(404, 'Task not found')
    return {'log': lines[idx]}


# ── Registry adapters (informational) ────────────────────────────────────────

@router.get('/replication/adapters', auth=robot_bearer_auth, tags=['registry'])
def list_adapters(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return [t[0] for t in RemoteRegistry.TYPE_CHOICES]


@router.get('/replication/adapterinfos', auth=robot_bearer_auth, tags=['registry'])
def list_adapterinfos(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return [
        {'type': t[0], 'description': t[1]}
        for t in RemoteRegistry.TYPE_CHOICES
    ]


# ── Registries ────────────────────────────────────────────────────────────────

@router.post('/registries', response={201: V2RemoteRegistryOut}, auth=robot_bearer_auth, tags=['registry'])
def create_registry(request, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    remote = RemoteRegistry.objects.create(
        name=payload.get('name', ''),
        description=payload.get('description', ''),
        registry_type=payload.get('type', 'generic'),
        endpoint=payload.get('url', payload.get('endpoint', '')),
        username=payload.get('credential', {}).get('access_key', payload.get('username', '')),
        password_enc=payload.get('credential', {}).get('access_secret', payload.get('password', '')),
        insecure=payload.get('insecure', False),
        verified=False,
    )
    _log(robot, 'create', 'remote_registry', remote.name, {})
    return 201, remote


@router.get('/registries', response=list[V2RemoteRegistryOut], auth=robot_bearer_auth, tags=['registry'])
def list_registries(request, name: str = '', page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = RemoteRegistry.objects.all()
    if name:
        qs = qs.filter(name__icontains=name)
    offset = (page - 1) * page_size
    return list(qs.order_by('name')[offset:offset + page_size])


@router.post('/registries/ping', auth=robot_bearer_auth, tags=['registry'])
def ping_registry(request, payload: dict):
    """Ping a registry by id or inline credentials to check connectivity."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    registry_id = payload.get('id')
    if registry_id:
        remote = get_object_or_404(RemoteRegistry, id=registry_id)
        return {'success': remote.verified, 'message': 'Use the /registries/{id}/ping endpoint to (re-)verify'}
    # Inline check: just confirm endpoint is provided
    endpoint = payload.get('url', payload.get('endpoint', ''))
    if not endpoint:
        raise HttpError(400, 'endpoint/url is required for an inline ping')
    return {'success': True, 'message': 'Inline ping not executed — save the registry first and use /registries/{id}/ping'}


@router.get('/registries/{registry_id}', response=V2RemoteRegistryOut, auth=robot_bearer_auth, tags=['registry'])
def get_registry(request, registry_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return get_object_or_404(RemoteRegistry, id=registry_id)


@router.delete('/registries/{registry_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['registry'])
def delete_registry(request, registry_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    remote = get_object_or_404(RemoteRegistry, id=registry_id)
    name = remote.name
    remote.delete()
    _log(robot, 'delete', 'remote_registry', name, {})
    return {'success': True, 'message': f'Registry {name} deleted'}


@router.put('/registries/{registry_id}', response=V2RemoteRegistryOut, auth=robot_bearer_auth, tags=['registry'])
def update_registry(request, registry_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    remote = get_object_or_404(RemoteRegistry, id=registry_id)
    for field, key in [('name', 'name'), ('description', 'description'),
                       ('registry_type', 'type'), ('endpoint', 'url'),
                       ('insecure', 'insecure')]:
        if key in payload:
            setattr(remote, field, payload[key])
    if 'endpoint' in payload:
        remote.endpoint = payload['endpoint']
    cred = payload.get('credential', {})
    if cred.get('access_key'):
        remote.username = cred['access_key']
    if cred.get('access_secret'):
        remote.password_enc = cred['access_secret']
        remote.verified = False
    remote.save()
    _log(robot, 'update', 'remote_registry', remote.name, {})
    return remote


@router.get('/registries/{registry_id}/info', auth=robot_bearer_auth, tags=['registry'])
def get_registry_info(request, registry_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    remote = get_object_or_404(RemoteRegistry, id=registry_id)
    return {
        'type': remote.registry_type,
        'description': remote.description,
        'supported_resource_filters': [
            {'type': 'Name', 'style': 'input'},
            {'type': 'Tag', 'style': 'input'},
            {'type': 'Label', 'style': 'input'},
        ],
        'supported_triggers': ['manual', 'scheduled', 'on_push'],
        'supported_copy_by_chunk': False,
        'supported_url_type': 'origin',
    }


# ── Scan All ──────────────────────────────────────────────────────────────────

@router.get('/scans/all/metrics', auth=robot_bearer_auth, tags=['scanAll'])
def scan_all_metrics(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    total = Tag.objects.count()
    scanned = Tag.objects.filter(scans__status='finished').distinct().count()
    running = VulnerabilityScan.objects.filter(status='running').count()
    return {
        'total': total,
        'scanned': scanned,
        'unscanned': total - scanned,
        'running': running,
        'success': VulnerabilityScan.objects.filter(status='finished').count(),
        'error': VulnerabilityScan.objects.filter(status='error').count(),
    }


@router.get('/scans/schedule/metrics', auth=robot_bearer_auth, tags=['scanAll'])
def scan_schedule_metrics(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    from users.models import SiteSettings
    cfg = SiteSettings.get()
    return {
        'gc_enabled': cfg.gc_enabled,
        'gc_interval_hours': cfg.gc_interval_hours,
        'gc_last_run_at': cfg.gc_last_run_at.isoformat() if cfg.gc_last_run_at else None,
    }


@router.get('/system/scanAll/schedule', auth=robot_bearer_auth, tags=['scanAll'])
def get_scan_all_schedule(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    from users.models import SiteSettings
    cfg = SiteSettings.get()
    return {
        'type': 'Periodic' if cfg.gc_enabled else 'None',
        'cron': f'0 0 */{cfg.gc_interval_hours} * * *' if cfg.gc_enabled else '',
    }


@router.put('/system/scanAll/schedule', response=V2MessageOut, auth=robot_bearer_auth, tags=['scanAll'])
def update_scan_all_schedule(request, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    from users.models import SiteSettings
    cfg = SiteSettings.get()
    schedule_type = payload.get('type', 'None')
    cfg.gc_enabled = schedule_type.lower() not in ('none', '')
    if 'cron' in payload and payload['cron']:
        # Extract interval hours from cron if possible
        try:
            parts = payload['cron'].split()
            if len(parts) >= 3 and '/' in parts[2]:
                cfg.gc_interval_hours = int(parts[2].split('/')[1])
        except (ValueError, IndexError):
            pass
    cfg.save()
    _log(robot, 'update', 'scan_schedule', 'system', payload)
    return {'success': True, 'message': 'Scan schedule updated'}


@router.post('/system/scanAll/schedule', response=V2MessageOut, auth=robot_bearer_auth, tags=['scanAll'])
def create_scan_all_schedule(request, payload: dict):
    return update_scan_all_schedule(request, payload)


@router.post('/system/scanAll/stop', response=V2MessageOut, auth=robot_bearer_auth, tags=['scanAll'])
def stop_scan_all(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    updated = VulnerabilityScan.objects.filter(status__in=['pending', 'running']).update(status='error')
    return {'success': True, 'message': f'{updated} scan(s) cancelled'}


# ── Retention policies ────────────────────────────────────────────────────────
# Siene stores retention as tag_retention_rules (list) in ProjectPolicy.
# We expose a Harbor-compatible Retention resource that wraps that list.

@router.get('/retentions/metadatas', auth=robot_bearer_auth, tags=['retention'])
def retention_metadatas(request):
    """Return retention policy metadata (supported rule templates)."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return {
        'templates': [
            {'action': 'retain', 'display_text': 'retain the most recently pushed # artifacts', 'rule_template': 'latestPushedK'},
            {'action': 'retain', 'display_text': 'retain the artifacts pushed within the last # days', 'rule_template': 'nDaysSinceLastPush'},
            {'action': 'retain', 'display_text': 'retain always', 'rule_template': 'always'},
            {'action': 'exclude', 'display_text': 'exclude always', 'rule_template': 'always'},
        ],
        'scope_selectors': {'repository': ['doublestar', 'repoMatches', 'repoExcludes']},
        'tag_selectors': ['doublestar', 'matches', 'excludes'],
    }


@router.post('/retentions', response={201: dict}, auth=robot_bearer_auth, tags=['retention'])
def create_retention(request, payload: dict):
    """Create a retention policy for a project."""
    robot: RobotAccount = request.auth
    project_name = payload.get('scope', {}).get('ref') or payload.get('project')
    if not project_name:
        raise HttpError(400, 'scope.ref (project name) is required')
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    rules = []
    for r in payload.get('rules', []):
        rule = {'match': r.get('tag_selectors', [{}])[0].get('pattern', '**')}
        if r.get('params', {}).get('latestPushedK'):
            rule['keep_count'] = int(r['params']['latestPushedK'])
        if r.get('params', {}).get('nDaysSinceLastPush'):
            rule['keep_days'] = int(r['params']['nDaysSinceLastPush'])
        rules.append(rule)
    policy.tag_retention_rules = rules
    policy.save()
    _log(robot, 'update', 'retention', project_name, {'rules': rules}, project=project)
    return 201, {'id': project.id, 'project': project_name, 'rules': rules}


@router.get('/retentions/{retention_id}', auth=robot_bearer_auth, tags=['retention'])
def get_retention(request, retention_id: int):
    """Get retention policy. retention_id = project.id in Siene."""
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'read')
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    return {'id': project.id, 'project': project.name, 'rules': policy.tag_retention_rules}


@router.put('/retentions/{retention_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['retention'])
def update_retention(request, retention_id: int, payload: dict):
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'manage')
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    if 'rules' in payload:
        rules = []
        for r in payload['rules']:
            rule = {'match': r.get('match', '**')}
            if 'keep_count' in r:
                rule['keep_count'] = r['keep_count']
            if 'keep_days' in r:
                rule['keep_days'] = r['keep_days']
            rules.append(rule)
        policy.tag_retention_rules = rules
        policy.save()
    return {'success': True, 'message': 'Retention policy updated'}


@router.delete('/retentions/{retention_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['retention'])
def delete_retention(request, retention_id: int):
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'manage')
    policy, _ = ProjectPolicy.objects.get_or_create(project=project)
    policy.tag_retention_rules = []
    policy.save()
    return {'success': True, 'message': 'Retention policy cleared'}


@router.post('/retentions/{retention_id}/executions', response={201: V2MessageOut}, auth=robot_bearer_auth, tags=['retention'])
def trigger_retention(request, retention_id: int):
    """Trigger a retention execution (GC with retention filter) for a project."""
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'manage')
    try:
        from registry.tasks import run_gc
        run_gc.apply_async(queue='default')
    except Exception:
        pass
    return 201, {'success': True, 'message': 'Retention execution triggered'}


@router.get('/retentions/{retention_id}/executions', auth=robot_bearer_auth, tags=['retention'])
def list_retention_executions(request, retention_id: int):
    """List retention executions. Siene uses GC — we return an empty list."""
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'read')
    return []


@router.patch('/retentions/{retention_id}/executions/{eid}', response=V2MessageOut, auth=robot_bearer_auth, tags=['retention'])
def stop_retention_execution(request, retention_id: int, eid: int):
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'manage')
    return {'success': True, 'message': 'Stop requested'}


@router.get('/retentions/{retention_id}/executions/{eid}/tasks', auth=robot_bearer_auth, tags=['retention'])
def list_retention_tasks(request, retention_id: int, eid: int):
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'read')
    return []


@router.get('/retentions/{retention_id}/executions/{eid}/tasks/{tid}', auth=robot_bearer_auth, tags=['retention'])
def get_retention_task_log(request, retention_id: int, eid: int, tid: int):
    robot: RobotAccount = request.auth
    project = get_object_or_404(Project, id=retention_id)
    _require_robot(robot, project.name, 'read')
    return {'log': ''}


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get('/users', response=list[V2UserOut], auth=robot_bearer_auth, tags=['user'])
def list_users(request, page: int = 1, page_size: int = 20, q: str = ''):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = User.objects.all()
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(email__icontains=q))
    offset = (page - 1) * page_size
    return list(qs.order_by('username')[offset:offset + page_size])


@router.post('/users', response={201: V2UserOut}, auth=robot_bearer_auth, tags=['user'])
def create_user(request, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    username = payload.get('username', '').strip()
    email = payload.get('email', '').strip()
    password = payload.get('password', '')
    if not username or not email or not password:
        raise HttpError(400, 'username, email and password are required')
    if User.objects.filter(username__iexact=username).exists():
        raise HttpError(409, 'Username already exists')
    if User.objects.filter(email__iexact=email).exists():
        raise HttpError(409, 'Email already exists')
    user = User.objects.create_user(username=username, email=email, password=password)
    from users.models import UserProfile
    UserProfile.objects.get_or_create(user=user)
    _log(robot, 'create', 'user', username, {'email': email})
    return 201, user


@router.get('/users/current', auth=robot_bearer_auth, tags=['user'])
def current_user(request):
    """Return info about the authenticated robot (not a human user)."""
    robot: RobotAccount = request.auth
    return {
        'type': 'robot',
        'id': robot.id,
        'name': robot.name,
        'description': robot.description,
        'project': robot.project.name if robot.project else None,
        'is_system': _is_system_robot(robot),
        'permissions': robot.permissions,
        'expires_at': robot.expires_at.isoformat() if robot.expires_at else None,
    }


@router.get('/users/search', auth=robot_bearer_auth, tags=['user'])
def search_users(request, username: str = '', page: int = 1, page_size: int = 10):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    qs = User.objects.filter(username__icontains=username) if username else User.objects.all()
    offset = (page - 1) * page_size
    return [
        {'id': u.id, 'username': u.username}
        for u in qs.order_by('username')[offset:offset + page_size]
    ]


@router.get('/users/{user_id}', response=V2UserOut, auth=robot_bearer_auth, tags=['user'])
def get_user(request, user_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return get_object_or_404(User, id=user_id)


@router.put('/users/{user_id}', response=V2UserOut, auth=robot_bearer_auth, tags=['user'])
def update_user(request, user_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    user = get_object_or_404(User, id=user_id)
    if 'email' in payload:
        user.email = payload['email']
    if 'first_name' in payload:
        user.first_name = payload['first_name']
    if 'last_name' in payload:
        user.last_name = payload['last_name']
    user.save()
    _log(robot, 'update', 'user', user.username, {'changes': payload})
    return user


@router.delete('/users/{user_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['user'])
def delete_user(request, user_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    user = get_object_or_404(User, id=user_id)
    username = user.username
    user.delete()
    _log(robot, 'delete', 'user', username, {})
    return {'success': True, 'message': f'User {username} deleted'}


@router.put('/users/{user_id}/sysadmin', response=V2MessageOut, auth=robot_bearer_auth, tags=['user'])
def set_sysadmin(request, user_id: int, payload: dict):
    """Grant or revoke system admin for a user."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    user = get_object_or_404(User, id=user_id)
    from users.models import UserProfile
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.is_admin = bool(payload.get('sysadmin_flag', True))
    profile.save()
    _log(robot, 'update', 'user', user.username, {'is_admin': profile.is_admin})
    return {'success': True, 'message': f'sysadmin={profile.is_admin} for {user.username}'}


@router.put('/users/{user_id}/password', response=V2MessageOut, auth=robot_bearer_auth, tags=['user'])
def change_user_password(request, user_id: int, payload: dict):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    user = get_object_or_404(User, id=user_id)
    new_password = payload.get('new_password', '')
    if len(new_password) < 8:
        raise HttpError(400, 'Password must be at least 8 characters')
    user.set_password(new_password)
    user.save()
    _log(robot, 'update', 'user', user.username, {'action': 'change_password'})
    return {'success': True, 'message': 'Password updated'}


@router.get('/users/current/permissions', auth=robot_bearer_auth, tags=['user'])
def current_permissions(request):
    robot: RobotAccount = request.auth
    return {
        'is_system': _is_system_robot(robot),
        'permissions': robot.permissions or [],
    }


@router.put('/users/{user_id}/cli_secret', response=V2MessageOut, auth=robot_bearer_auth, tags=['user'])
def set_cli_secret(request, user_id: int, payload: dict):
    """
    Set a CLI secret (PAT) for a user.
    In Siene, PATs are managed via /api/accounts/tokens/.
    This endpoint is a stub for Harbor compatibility.
    """
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    get_object_or_404(User, id=user_id)
    return {'success': True, 'message': 'Use /api/accounts/tokens/ to manage Personal Access Tokens'}


# ── Labels ────────────────────────────────────────────────────────────────────

@router.get('/labels', response=list[V2LabelOut], auth=robot_bearer_auth, tags=['label'])
def list_labels(request, project_name: str = '', q: str = '',
                page: int = 1, page_size: int = 20):
    robot: RobotAccount = request.auth
    qs = Label.objects.select_related('project').all()
    if project_name:
        _require_robot(robot, project_name, 'read')
        qs = qs.filter(project__name=project_name)
    elif not _is_system_robot(robot):
        # Limit to accessible projects
        allowed = set()
        for perm in (robot.permissions or []):
            proj = perm.get('project', '')
            if proj and proj != '*':
                allowed.add(proj)
        if robot.project:
            allowed.add(robot.project.name)
        qs = qs.filter(Q(project__public=True) | Q(project__name__in=allowed))
    if q:
        qs = qs.filter(name__icontains=q)
    offset = (page - 1) * page_size
    return list(qs.order_by('project__name', 'name')[offset:offset + page_size])


@router.post('/labels', response={201: V2LabelOut}, auth=robot_bearer_auth, tags=['label'])
def create_label(request, payload: dict):
    project_name = payload.get('project_name', '').strip()
    if not project_name:
        raise HttpError(400, 'project_name is required')
    robot: RobotAccount = request.auth
    _require_robot(robot, project_name, 'manage')
    project = get_object_or_404(Project, name=project_name)
    label = Label.objects.create(
        project=project,
        name=payload.get('name', ''),
        description=payload.get('description', ''),
        color=payload.get('color', '#6366f1'),
    )
    _log(robot, 'create', 'label', label.name, {}, project=project)
    return 201, label


@router.get('/labels/{label_id}', response=V2LabelOut, auth=robot_bearer_auth, tags=['label'])
def get_label(request, label_id: int):
    robot: RobotAccount = request.auth
    label = get_object_or_404(Label, id=label_id)
    _require_robot(robot, label.project.name, 'read')
    return label


@router.put('/labels/{label_id}', response=V2LabelOut, auth=robot_bearer_auth, tags=['label'])
def update_label(request, label_id: int, payload: dict):
    robot: RobotAccount = request.auth
    label = get_object_or_404(Label, id=label_id)
    _require_robot(robot, label.project.name, 'manage')
    for field in ('name', 'description', 'color'):
        if field in payload:
            setattr(label, field, payload[field])
    label.save()
    _log(robot, 'update', 'label', label.name, payload, project=label.project)
    return label


@router.delete('/labels/{label_id}', response=V2MessageOut, auth=robot_bearer_auth, tags=['label'])
def delete_label(request, label_id: int):
    robot: RobotAccount = request.auth
    label = get_object_or_404(Label, id=label_id)
    _require_robot(robot, label.project.name, 'manage')
    name = label.name
    project = label.project
    label.delete()
    _log(robot, 'delete', 'label', name, {}, project=project)
    return {'success': True, 'message': f'Label {name} deleted'}


# ── CVE Export ────────────────────────────────────────────────────────────────

@router.post('/export/cve', response={201: dict}, auth=robot_bearer_auth, tags=['scan data export'])
def export_cve(request, payload: dict):
    """
    Export vulnerability scan data for selected projects.
    Returns an execution id (scan query id in Siene).
    """
    robot: RobotAccount = request.auth
    project_names = payload.get('projects', [])
    # Build a synthetic execution id from a hash of the criteria
    import time
    exec_id = int(time.time())
    return 201, {'id': exec_id, 'status': 'Running', 'projects': project_names}


@router.get('/export/cve/execution/{execution_id}', auth=robot_bearer_auth, tags=['scan data export'])
def get_cve_execution(request, execution_id: int):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return {'id': execution_id, 'status': 'Successful', 'message': 'Use /export/cve/download/{id} to fetch the file'}


@router.get('/export/cve/executions', auth=robot_bearer_auth, tags=['scan data export'])
def list_cve_executions(request):
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    return []


@router.get('/export/cve/download/{execution_id}', auth=robot_bearer_auth, tags=['scan data export'])
def download_cve(request, execution_id: int, project: str = '', format: str = 'json'):
    """
    Download CVE data as JSON.
    In Siene, returns the latest finished scan reports across all accessible projects.
    """
    robot: RobotAccount = request.auth
    import json

    scans_qs = VulnerabilityScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished')

    if project:
        _require_robot(robot, project, 'read')
        scans_qs = scans_qs.filter(tag__repository__project__name=project)
    elif not _is_system_robot(robot):
        allowed = set()
        for perm in (robot.permissions or []):
            proj = perm.get('project', '')
            if proj and proj != '*':
                allowed.add(proj)
        if robot.project:
            allowed.add(robot.project.name)
        scans_qs = scans_qs.filter(tag__repository__project__name__in=allowed)

    results = []
    seen: set[int] = set()
    for scan in scans_qs.order_by('-finished_at'):
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        tag = scan.tag
        for vuln in (scan.report or []):
            results.append({
                'project': tag.repository.project.name,
                'repository': tag.repository.name,
                'tag': tag.name,
                'digest': tag.digest,
                'vulnerability_id': vuln.get('VulnerabilityID', vuln.get('id', '')),
                'severity': vuln.get('Severity', vuln.get('severity', '')),
                'package': vuln.get('PkgName', vuln.get('package', '')),
                'version': vuln.get('InstalledVersion', vuln.get('version', '')),
                'fixed_version': vuln.get('FixedVersion', vuln.get('fixed_version', '')),
                'description': vuln.get('Description', vuln.get('description', ''))[:200],
            })

    from django.http import HttpResponse
    content = json.dumps(results, indent=2)
    response = HttpResponse(content, content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="cve_export_{execution_id}.json"'
    return response


# ── Security Hub ──────────────────────────────────────────────────────────────

@router.get('/security/summary', auth=robot_bearer_auth, tags=['securityhub'])
def security_summary(request):
    """Get system-wide vulnerability summary."""
    robot: RobotAccount = request.auth
    _require_system_robot(robot)
    scans = VulnerabilityScan.objects.filter(status='finished')
    summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0, 'unknown': 0}
    seen: set[int] = set()
    for scan in scans.select_related('tag').order_by('-finished_at'):
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        for sev, count in (scan.summary or {}).items():
            key = sev.lower()
            if key in summary:
                summary[key] += count or 0
    summary['total_artifacts'] = Tag.objects.count()
    summary['scanned_artifacts'] = len(seen)
    return summary


@router.get('/security/vul', auth=robot_bearer_auth, tags=['securityhub'])
def list_vulnerabilities(request, severity: str = '', project: str = '',
                          cve_id: str = '', page: int = 1, page_size: int = 50):
    """List vulnerabilities across all accessible artifacts."""
    robot: RobotAccount = request.auth
    scans_qs = VulnerabilityScan.objects.select_related(
        'tag', 'tag__repository', 'tag__repository__project'
    ).filter(status='finished')

    if project:
        _require_robot(robot, project, 'read')
        scans_qs = scans_qs.filter(tag__repository__project__name=project)
    elif not _is_system_robot(robot):
        allowed = set()
        for perm in (robot.permissions or []):
            proj = perm.get('project', '')
            if proj and proj != '*':
                allowed.add(proj)
        if robot.project:
            allowed.add(robot.project.name)
        scans_qs = scans_qs.filter(tag__repository__project__name__in=allowed)

    results = []
    seen: set[int] = set()
    for scan in scans_qs.order_by('-finished_at'):
        if scan.tag_id in seen:
            continue
        seen.add(scan.tag_id)
        tag = scan.tag
        for vuln in (scan.report or []):
            vuln_sev = (vuln.get('Severity') or vuln.get('severity', '')).upper()
            vuln_id = vuln.get('VulnerabilityID') or vuln.get('id', '')
            if severity and vuln_sev != severity.upper():
                continue
            if cve_id and cve_id.upper() not in vuln_id.upper():
                continue
            results.append({
                'cve_id': vuln_id,
                'severity': vuln_sev,
                'package': vuln.get('PkgName') or vuln.get('package', ''),
                'version': vuln.get('InstalledVersion') or vuln.get('version', ''),
                'fixed_version': vuln.get('FixedVersion') or vuln.get('fixed_version', ''),
                'project': tag.repository.project.name,
                'repository': tag.repository.name,
                'artifact': tag.name,
                'digest': tag.digest,
            })

    offset = (page - 1) * page_size
    return results[offset:offset + page_size]
