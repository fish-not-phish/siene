from ninja import Schema
from typing import Optional
from datetime import datetime


# ── Projects ──────────────────────────────────────────────────────────────────

class ProjectIn(Schema):
    name: str
    display_name: str = ''
    description: str = ''
    public: bool = False
    quota_gb: Optional[float] = None


class ProjectPatchIn(Schema):
    display_name: Optional[str] = None
    description: Optional[str] = None
    public: Optional[bool] = None
    quota_gb: Optional[float] = None


class ProjectOut(Schema):
    id: int
    name: str
    display_name: str
    description: str
    public: bool
    quota_gb: Optional[float]
    owner_username: Optional[str]
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def resolve_owner_username(obj):
        return obj.owner.username if obj.owner else None


class ProjectSummaryOut(Schema):
    repo_count: int
    tag_count: int
    storage_bytes: int


# ── Members ───────────────────────────────────────────────────────────────────

class MemberIn(Schema):
    username: str
    role: str


class MemberPatchIn(Schema):
    role: str


class MemberOut(Schema):
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


# ── Repositories ──────────────────────────────────────────────────────────────

class RepositoryOut(Schema):
    id: int
    name: str
    full_name: str
    description: str
    pull_count: int
    push_count: int
    tag_count: int
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def resolve_tag_count(obj):
        return obj.tags.count()


class RepositoryPatchIn(Schema):
    description: Optional[str] = None


# ── Labels ────────────────────────────────────────────────────────────────────
# Defined here (before TagOut) so TagOut.labels: list[LabelOut] resolves at class-definition time.

class LabelOut(Schema):
    id: int
    name: str
    description: str
    color: str
    created_at: datetime


# ── Tags ──────────────────────────────────────────────────────────────────────

class SignatureStatusOut(Schema):
    cosign: str
    notation: str
    cosign_output: str
    notation_output: str
    checked_at: Optional[datetime]


class PlatformChildOut(Schema):
    """Lightweight summary of a per-platform child tag shown on an index tag's detail page."""
    id: int
    name: str
    platform: str
    digest: str
    os: str
    architecture: str
    size_bytes: int
    scan_status: Optional[str]
    secret_scan_status: Optional[str]
    misconfig_scan_status: Optional[str]
    sbom_status: Optional[str]

    @staticmethod
    def resolve_scan_status(obj):
        latest = obj.scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_secret_scan_status(obj):
        latest = obj.secret_scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_misconfig_scan_status(obj):
        latest = obj.misconfig_scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_sbom_status(obj):
        latest = obj.sbom_reports.first()
        return latest.status if latest else None


def _aggregate_child_scan_status(children, scan_rel: str) -> Optional[str]:
    """Return a single representative status aggregated from all platform children.

    Priority order (worst → best):
      error > running > pending > finished > None
    """
    statuses = []
    for child in children:
        mgr = getattr(child, scan_rel, None)
        if mgr is not None:
            latest = mgr.first()
            if latest:
                statuses.append(latest.status)
    if not statuses:
        return None
    if 'error' in statuses:
        return 'error'
    if 'running' in statuses:
        return 'running'
    if 'pending' in statuses:
        return 'pending'
    if 'finished' in statuses:
        return 'finished'
    return statuses[0]


class TagOut(Schema):
    id: int
    name: str
    digest: str
    size_bytes: int
    os: str
    architecture: str
    pushed_by_username: Optional[str]
    pushed_at: datetime
    last_activity_at: Optional[datetime]
    scan_status: Optional[str]
    secret_scan_status: Optional[str]
    misconfig_scan_status: Optional[str]
    sbom_status: Optional[str]
    labels: list[LabelOut]
    cosign_status: str
    notation_status: str
    # Multi-arch fields
    is_index: bool
    platform: str

    @staticmethod
    def resolve_pushed_by_username(obj):
        return obj.pushed_by.username if obj.pushed_by else None

    @staticmethod
    def resolve_scan_status(obj):
        if obj.is_index:
            children = list(obj.platform_children.prefetch_related('scans').all())
            return _aggregate_child_scan_status(children, 'scans')
        latest = obj.scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_secret_scan_status(obj):
        if obj.is_index:
            children = list(obj.platform_children.prefetch_related('secret_scans').all())
            return _aggregate_child_scan_status(children, 'secret_scans')
        latest = obj.secret_scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_misconfig_scan_status(obj):
        if obj.is_index:
            children = list(obj.platform_children.prefetch_related('misconfig_scans').all())
            return _aggregate_child_scan_status(children, 'misconfig_scans')
        latest = obj.misconfig_scans.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_sbom_status(obj):
        if obj.is_index:
            children = list(obj.platform_children.prefetch_related('sbom_reports').all())
            return _aggregate_child_scan_status(children, 'sbom_reports')
        latest = obj.sbom_reports.first()
        return latest.status if latest else None

    @staticmethod
    def resolve_labels(obj):
        return list(obj.labels.all())

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


class TagDetailOut(TagOut):
    manifest: dict
    image_config: dict
    index_manifest: dict
    platform_children: list[PlatformChildOut]

    @staticmethod
    def resolve_platform_children(obj):
        if not obj.is_index:
            return []
        return list(obj.platform_children.prefetch_related(
            'scans', 'secret_scans', 'misconfig_scans', 'sbom_reports'
        ).all())


class TagLabelIn(Schema):
    """Set the complete list of label IDs on a tag (replaces existing assignment)."""
    label_ids: list[int]


class SBOMReportOut(Schema):
    status: str
    created_at: Optional[datetime]
    finished_at: Optional[datetime]
    report: dict


# ── Robot Accounts ────────────────────────────────────────────────────────────

class RobotIn(Schema):
    name: str
    description: str = ''
    permissions: list = []
    expires_at: Optional[datetime] = None


class RobotPatchIn(Schema):
    description: Optional[str] = None
    disabled: Optional[bool] = None
    permissions: Optional[list] = None
    expires_at: Optional[datetime] = None


class RobotOut(Schema):
    id: int
    name: str
    description: str
    permissions: list
    expires_at: Optional[datetime]
    disabled: bool
    created_at: datetime


class RobotCreatedOut(RobotOut):
    """Returned once on creation — includes plaintext secret."""
    secret: str


# ── Audit Logs ────────────────────────────────────────────────────────────────

class AuditLogOut(Schema):
    id: int
    username: str
    project_name: Optional[str]
    resource_type: str
    resource: str
    operation: str
    result: bool
    detail: dict
    timestamp: datetime

    @staticmethod
    def resolve_project_name(obj):
        return obj.project.name if obj.project else None


# ── System ────────────────────────────────────────────────────────────────────

class SystemStatsOut(Schema):
    project_count: int
    repository_count: int
    tag_count: int
    user_count: int
    storage_bytes: int


# ── Vulnerability Scans ───────────────────────────────────────────────────────

class ScanSummaryOut(Schema):
    status: str
    summary: dict
    started_at: Optional[datetime]
    finished_at: Optional[datetime]


class ScanReportOut(ScanSummaryOut):
    report: list


# ── Labels ───────────────────────────────────────────────────────────────────

class LabelIn(Schema):
    name: str
    description: str = ''
    color: str = '#6366f1'


class LabelPatchIn(Schema):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None


# ── Remote Registries ─────────────────────────────────────────────────────────

class RemoteRegistryIn(Schema):
    name: str
    description: str = ''
    registry_type: str = 'generic'
    endpoint: str
    username: str = ''
    password: str = ''
    insecure: bool = False


class RemoteRegistryPatchIn(Schema):
    name: Optional[str] = None
    description: Optional[str] = None
    registry_type: Optional[str] = None
    endpoint: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    insecure: Optional[bool] = None


class RemoteRegistryOut(Schema):
    id: int
    name: str
    description: str
    registry_type: str
    endpoint: str
    username: str
    insecure: bool
    verified: bool
    created_at: datetime
    updated_at: datetime


# ── Replication Rules ─────────────────────────────────────────────────────────

class ReplicationRuleIn(Schema):
    name: str
    description: str = ''
    remote_id: int
    direction: str = 'push'
    # filters
    source_filter: str = ''
    tag_filter: str = ''
    label_filter: str = ''
    resource_type: str = 'all'
    # destination
    destination_namespace: str = ''
    flatten_mode: str = 'flatten_1'
    # trigger
    trigger: str = 'manual'
    schedule: str = ''
    # behaviour
    bandwidth_limit_kb: int = -1
    override_existing: bool = True
    single_active: bool = False
    delete_remote_on_local_delete: bool = False
    enabled: bool = True


class ReplicationRulePatchIn(Schema):
    name: Optional[str] = None
    description: Optional[str] = None
    source_filter: Optional[str] = None
    tag_filter: Optional[str] = None
    label_filter: Optional[str] = None
    resource_type: Optional[str] = None
    destination_namespace: Optional[str] = None
    flatten_mode: Optional[str] = None
    trigger: Optional[str] = None
    schedule: Optional[str] = None
    bandwidth_limit_kb: Optional[int] = None
    override_existing: Optional[bool] = None
    single_active: Optional[bool] = None
    delete_remote_on_local_delete: Optional[bool] = None
    enabled: Optional[bool] = None


class ReplicationRuleOut(Schema):
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
    last_run_at: Optional[datetime]
    last_run_status: str
    created_at: datetime
    updated_at: datetime

    @staticmethod
    def resolve_remote_id(obj):
        return obj.remote_id

    @staticmethod
    def resolve_remote_name(obj):
        return obj.remote.name


# ── Security Hub ──────────────────────────────────────────────────────────────

class VulnSummaryOut(Schema):
    """Per-tag vulnerability summary for the system-wide security hub."""
    tag_id: int
    tag_name: str
    repository: str
    project: str
    scan_status: str
    critical: int
    high: int
    medium: int
    low: int
    scanned_at: Optional[datetime]


class SecretSummaryOut(Schema):
    """Per-tag secret scan summary."""
    tag_id: int
    tag_name: str
    repository: str
    project: str
    scan_status: str
    total: int
    scanned_at: Optional[datetime]


class MisconfigSummaryOut(Schema):
    """Per-tag misconfiguration scan summary."""
    tag_id: int
    tag_name: str
    repository: str
    project: str
    scan_status: str
    fail: int
    warn: int
    pass_count: int
    scanned_at: Optional[datetime]


# ── Secret Scans ─────────────────────────────────────────────────────────────

class SecretScanReportOut(Schema):
    status: str
    total: int
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    report: list


# ── Misconfig Scans ───────────────────────────────────────────────────────────

class MisconfigScanReportOut(Schema):
    status: str
    summary: dict
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    report: list


# ── Project Policy ───────────────────────────────────────────────────────────

class TagRetentionRule(Schema):
    """A single tag-retention rule within a project policy."""
    match: str = '**'                     # glob pattern, e.g. "v*" or "**"
    keep_count: Optional[int] = None      # keep the N most-recent matching tags
    keep_days: Optional[int] = None       # keep tags pushed within N days


class ProjectPolicyOut(Schema):
    sbom_enabled: bool
    scanning_enabled: bool
    secret_scanning_enabled: bool
    misconfig_scanning_enabled: bool
    cosign_required: bool
    notation_required: bool
    prevent_vulnerable_images: bool
    vuln_block_rules: dict
    prevent_secret_images: bool
    secret_block_threshold: Optional[int]
    prevent_misconfig_images: bool
    misconfig_fail_threshold: Optional[int]
    tag_immutability: bool
    tag_retention_rules: list
    vuln_rescan_enabled: bool
    vuln_rescan_interval_days: int
    vuln_rescan_active_only: bool
    vuln_rescan_active_days: int


class ProjectPolicyPatchIn(Schema):
    sbom_enabled: Optional[bool] = None
    scanning_enabled: Optional[bool] = None
    secret_scanning_enabled: Optional[bool] = None
    misconfig_scanning_enabled: Optional[bool] = None
    cosign_required: Optional[bool] = None
    notation_required: Optional[bool] = None
    prevent_vulnerable_images: Optional[bool] = None
    vuln_block_rules: Optional[dict] = None
    prevent_secret_images: Optional[bool] = None
    secret_block_threshold: Optional[int] = None
    prevent_misconfig_images: Optional[bool] = None
    misconfig_fail_threshold: Optional[int] = None
    tag_immutability: Optional[bool] = None
    tag_retention_rules: Optional[list] = None
    vuln_rescan_enabled: Optional[bool] = None
    vuln_rescan_interval_days: Optional[int] = None
    vuln_rescan_active_only: Optional[bool] = None
    vuln_rescan_active_days: Optional[int] = None


# ── User Search ───────────────────────────────────────────────────────────────

class CreateUserIn(Schema):
    username: str
    email: str
    password: str


class PatchUserIn(Schema):
    is_admin: bool


class UserSearchOut(Schema):
    id: int
    username: str
    email: str


# ── Auth Token (Docker CLI) ───────────────────────────────────────────────────

class TokenOut(Schema):
    token: str
    access_token: str
    expires_in: int
    issued_at: str


# ── Replication Jobs ──────────────────────────────────────────────────────────

class ReplicationJobOut(Schema):
    id: int
    rule_id: int
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    copied: int
    errors: int
    log: str

    @staticmethod
    def resolve_rule_id(obj):
        return obj.rule_id


# ── Paginated tags ────────────────────────────────────────────────────────────

class PaginatedTagsOut(Schema):
    total: int
    items: list[TagOut]


# ── CVE Allowlist ─────────────────────────────────────────────────────────────

class VulnAllowlistIn(Schema):
    cve_id: str
    reason: str = ''
    expires_at: Optional[datetime] = None
    tag_id: Optional[int] = None   # None = project-wide; set to target a specific tag


class VulnAllowlistPatchIn(Schema):
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class VulnAllowlistOut(Schema):
    id: int
    cve_id: str
    reason: str
    expires_at: Optional[datetime]
    created_at: datetime
    is_expired: bool
    tag_id: Optional[int]
    tag_name: Optional[str]
    added_by_username: Optional[str]

    @staticmethod
    def resolve_tag_id(obj):
        return obj.tag_id

    @staticmethod
    def resolve_tag_name(obj):
        return obj.tag.name if obj.tag_id else None

    @staticmethod
    def resolve_added_by_username(obj):
        return obj.added_by.username if obj.added_by_id else None


# ── Secret Allowlist ──────────────────────────────────────────────────────────

class SecretAllowlistIn(Schema):
    rule_id: str
    reason: str = ''
    expires_at: Optional[datetime] = None


class SecretAllowlistPatchIn(Schema):
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class SecretAllowlistOut(Schema):
    id: int
    rule_id: str
    reason: str
    expires_at: Optional[datetime]
    created_at: datetime
    is_expired: bool
    project_id: Optional[int]
    tag_id: Optional[int]
    added_by_username: Optional[str]

    @staticmethod
    def resolve_project_id(obj):
        return obj.project_id

    @staticmethod
    def resolve_tag_id(obj):
        return obj.tag_id

    @staticmethod
    def resolve_added_by_username(obj):
        return obj.added_by.username if obj.added_by_id else None


# ── Misconfig Allowlist ────────────────────────────────────────────────────────

class MisconfigAllowlistIn(Schema):
    check_id: str
    reason: str = ''
    expires_at: Optional[datetime] = None


class MisconfigAllowlistPatchIn(Schema):
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None


class MisconfigAllowlistOut(Schema):
    id: int
    check_id: str
    reason: str
    expires_at: Optional[datetime]
    created_at: datetime
    is_expired: bool
    project_id: Optional[int]
    tag_id: Optional[int]
    added_by_username: Optional[str]

    @staticmethod
    def resolve_project_id(obj):
        return obj.project_id

    @staticmethod
    def resolve_tag_id(obj):
        return obj.tag_id

    @staticmethod
    def resolve_added_by_username(obj):
        return obj.added_by.username if obj.added_by_id else None


# ── GC Dry Run ───────────────────────────────────────────────────────────────

class GcDryRunTagOut(Schema):
    project: str
    repo: str
    tag: str
    reason: str   # 'orphan' | 'retention'
    rule_pattern: Optional[str] = None


class GcDryRunOut(Schema):
    orphan_tags: list[GcDryRunTagOut]
    retention_tags: list[GcDryRunTagOut]
    scans_to_prune: int
    audit_logs_to_prune: int
    job_logs_to_prune: int
    # Counts summarised
    total_tags_to_delete: int
    errors: list[str]


# ── GC Job ───────────────────────────────────────────────────────────────────

class GCJobOut(Schema):
    id: int
    status: str
    triggered_by: str
    started_at: datetime
    finished_at: Optional[datetime]
    orphans_deleted: int
    retention_deleted: int
    audit_deleted: int
    errors: int
    blob_gc_ok: Optional[bool]
    blob_gc_output: str
    error: str


# ── Sync Job ──────────────────────────────────────────────────────────────────

class SyncJobOut(Schema):
    id: int
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    repos_created: int
    tags_created: int
    error: str


# ── Trivy Update Job ─────────────────────────────────────────────────────────

class TrivyUpdateJobOut(Schema):
    id: int
    status: str
    triggered_by: str
    started_at: datetime
    finished_at: Optional[datetime]
    error: str


# ── Tag retention preview ────────────────────────────────────────────────────

class RetentionPreviewIn(Schema):
    match: str
    keep_count: Optional[int] = None
    keep_days: Optional[int] = None


# ── Generic ───────────────────────────────────────────────────────────────────

class MessageOut(Schema):
    success: bool
    message: str
