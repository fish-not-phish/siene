from django.db import models
from django.contrib.auth.models import User
from registry.crypto import encrypt_field, decrypt_field


class Project(models.Model):
    """Top-level namespace; maps directly to a registry prefix."""

    name = models.SlugField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='owned_projects')
    public = models.BooleanField(default=False, help_text='Allow anonymous pulls')
    quota_gb = models.FloatField(null=True, blank=True, help_text='Storage quota in GB. Null = unlimited.')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class ProjectMember(models.Model):
    ROLE_GUEST = 'guest'
    ROLE_DEVELOPER = 'developer'
    ROLE_MAINTAINER = 'maintainer'
    ROLE_ADMIN = 'admin'

    ROLE_CHOICES = [
        (ROLE_GUEST, 'Guest'),
        (ROLE_DEVELOPER, 'Developer'),
        (ROLE_MAINTAINER, 'Maintainer'),
        (ROLE_ADMIN, 'Project Admin'),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='members')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='project_memberships')
    role = models.CharField(max_length=32, choices=ROLE_CHOICES, default=ROLE_DEVELOPER)

    class Meta:
        unique_together = ('project', 'user')

    def __str__(self):
        return f'{self.user.username} in {self.project.name} ({self.role})'


class Repository(models.Model):
    """A named image repository within a project."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='repositories')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    pull_count = models.PositiveIntegerField(default=0)
    push_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('project', 'name')
        ordering = ['name']

    @property
    def full_name(self):
        return f'{self.project.name}/{self.name}'

    def __str__(self):
        return self.full_name


class Tag(models.Model):
    """An OCI image tag (pointer to a manifest digest).

    Multi-arch images are stored as a two-level hierarchy:
      - Index tag  (is_index=True):  represents the manifest list / OCI index.
                                     Holds the raw index JSON in index_manifest.
                                     Has no scans of its own — security status
                                     is aggregated from its platform_children.
      - Child tags (parent_tag!=None): one per platform in the index.
                                     Named  <parent_tag_name>@<platform>
                                     (e.g. "latest@linux/amd64").
                                     Hold the per-platform manifest/image_config.
                                     All scan rows belong here.

    Single-arch tags (the vast majority) have is_index=False and parent_tag=None.
    """

    repository = models.ForeignKey(Repository, on_delete=models.CASCADE, related_name='tags')
    name = models.CharField(max_length=255)
    digest = models.CharField(max_length=128)  # sha256:...
    size_bytes = models.BigIntegerField(default=0)
    os = models.CharField(max_length=64, blank=True)
    architecture = models.CharField(max_length=64, blank=True)
    pushed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='pushed_tags'
    )
    pushed_at = models.DateTimeField(db_index=False)  # Set explicitly on push events only — never auto_now
    manifest = models.JSONField(default=dict, blank=True)
    image_config = models.JSONField(default=dict, blank=True)  # OCI image config blob (history, config, rootfs)
    labels = models.ManyToManyField('Label', blank=True, related_name='tags')

    # Last known push or pull activity — set explicitly on push/pull events so it
    # is never accidentally bumped by internal saves (unlike pushed_at auto_now).
    # Null until the first real event is recorded for this tag.
    last_activity_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text='Timestamp of most recent push or pull event for this tag.',
    )

    # ── Multi-arch fields ──────────────────────────────────────────────────────
    # is_index: True  → this row IS the OCI index / manifest list tag.
    #                    Scan rows live on child tags; security status is
    #                    aggregated across platform_children.
    # is_index: False → ordinary single-arch tag OR a per-platform child tag.
    is_index = models.BooleanField(
        default=False,
        db_index=True,
        help_text='True if this tag points to a multi-arch OCI index / manifest list.',
    )
    # Raw OCI index JSON — only set when is_index=True.
    index_manifest = models.JSONField(
        default=dict,
        blank=True,
        help_text='Full OCI index / manifest list JSON.  Populated only when is_index=True.',
    )
    # FK to the index tag — only set on per-platform child tags.
    parent_tag = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='platform_children',
        help_text='For per-platform child tags: the index tag this child belongs to.',
    )
    # Human-readable platform string, e.g. "linux/amd64", "linux/arm64/v8".
    # Empty for single-arch tags and index tags.
    platform = models.CharField(
        max_length=64,
        blank=True,
        help_text='Platform string for per-platform child tags (e.g. "linux/amd64").',
    )

    class Meta:
        unique_together = ('repository', 'name')
        ordering = ['-pushed_at']

    def __str__(self):
        return f'{self.repository.full_name}:{self.name}'


class RobotAccount(models.Model):
    """Service account for automated push/pull (CI/CD)."""

    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, null=True, blank=True, related_name='robot_accounts',
        help_text='Null = system-level robot'
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    secret_hash = models.CharField(max_length=255)
    permissions = models.JSONField(default=list, help_text='[{"resource": "repository", "action": "pull"}, ...]')
    expires_at = models.DateTimeField(null=True, blank=True)
    disabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_robots')

    class Meta:
        ordering = ['name']

    def __str__(self):
        scope = self.project.name if self.project else 'system'
        return f'robot${scope}+{self.name}'


class AuditLog(models.Model):
    """Immutable record of user/robot actions on registry resources."""

    OP_PUSH = 'push'
    OP_PULL = 'pull'
    OP_DELETE = 'delete'
    OP_CREATE = 'create'
    OP_UPDATE = 'update'
    OP_LOGIN = 'login'
    OP_SCAN_STARTED = 'scan_started'
    OP_SCAN_FINISHED = 'scan_finished'
    OP_SCAN_ERROR = 'scan_error'

    OPERATION_CHOICES = [
        (OP_PUSH, 'Push'),
        (OP_PULL, 'Pull'),
        (OP_DELETE, 'Delete'),
        (OP_CREATE, 'Create'),
        (OP_UPDATE, 'Update'),
        (OP_LOGIN, 'Login'),
        (OP_SCAN_STARTED, 'Scan started'),
        (OP_SCAN_FINISHED, 'Scan finished'),
        (OP_SCAN_ERROR, 'Scan error'),
    ]

    RESOURCE_IMAGE = 'image'
    RESOURCE_PROJECT = 'project'
    RESOURCE_MEMBER = 'member'
    RESOURCE_ROBOT = 'robot'

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    username = models.CharField(max_length=255, blank=True, help_text='Snapshot of username at log time')
    project = models.ForeignKey(
        Project, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs'
    )
    resource_type = models.CharField(max_length=64)
    resource = models.CharField(max_length=512, blank=True)
    operation = models.CharField(max_length=32, choices=OPERATION_CHOICES)
    result = models.BooleanField(default=True)
    detail = models.JSONField(
        default=dict,
        blank=True,
        help_text='Structured change data — fields vary by resource type',
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.username} {self.operation} {self.resource}'


class Label(models.Model):
    """Metadata tag that can be attached to repositories or tags within a project."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='labels')
    name = models.CharField(max_length=128)
    description = models.TextField(blank=True)
    color = models.CharField(max_length=16, default='#6366f1', help_text='Hex colour for UI display')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('project', 'name')
        ordering = ['name']

    def __str__(self):
        return f'{self.project.name}/{self.name}'


class RemoteRegistry(models.Model):
    """An external registry that can be used as a replication target or source."""

    TYPE_DOCKER_HUB = 'docker-hub'
    TYPE_DOCKER_REGISTRY = 'docker-registry'
    TYPE_GHCR = 'ghcr'
    TYPE_ECR = 'ecr'
    TYPE_GCR = 'gcr'
    TYPE_ACR_AZURE = 'acr-azure'
    TYPE_TCR = 'tcr'
    TYPE_SWR = 'swr'
    TYPE_HARBOR = 'harbor'
    TYPE_JFROG = 'jfrog'
    TYPE_GENERIC = 'generic'

    TYPE_CHOICES = [
        (TYPE_DOCKER_HUB,      'Docker Hub'),
        (TYPE_DOCKER_REGISTRY, 'Docker Registry'),
        (TYPE_GHCR,            'GitHub Container Registry (GHCR)'),
        (TYPE_ECR,             'Amazon ECR'),
        (TYPE_GCR,             'Google Container Registry (GCR)'),
        (TYPE_ACR_AZURE,       'Azure Container Registry (ACR)'),
        (TYPE_TCR,             'Tencent Container Registry (TCR)'),
        (TYPE_SWR,             'Huawei SWR'),
        (TYPE_HARBOR,          'Harbor'),
        (TYPE_JFROG,           'JFrog Artifactory'),
        (TYPE_GENERIC,         'Generic (OCI / Docker v2)'),
    ]

    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    registry_type = models.CharField(max_length=32, choices=TYPE_CHOICES, default=TYPE_GENERIC)
    endpoint = models.CharField(max_length=512, help_text='Base URL, e.g. https://registry.example.com')
    username = models.CharField(max_length=255, blank=True)
    password_enc = models.TextField(blank=True, help_text='Encrypted credential (Fernet). Never expose in API responses.')
    insecure = models.BooleanField(default=False, help_text='Skip TLS verification')
    verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f'{self.name} ({self.endpoint})'

    # ── Credential helpers ────────────────────────────────────────────────────

    def set_password(self, plaintext: str) -> None:
        """Encrypt and store a credential. Call save() afterwards."""
        self.password_enc = encrypt_field(plaintext)

    def get_password(self) -> str:
        """Return the decrypted plaintext credential."""
        return decrypt_field(self.password_enc)


class ReplicationRule(models.Model):
    """Defines an automated push or pull replication policy between this registry and a remote."""

    TRIGGER_MANUAL = 'manual'
    TRIGGER_PUSH = 'on_push'
    TRIGGER_SCHEDULED = 'scheduled'

    TRIGGER_CHOICES = [
        (TRIGGER_MANUAL, 'Manual'),
        (TRIGGER_PUSH, 'On push'),
        (TRIGGER_SCHEDULED, 'Scheduled'),
    ]

    DIRECTION_PUSH = 'push'
    DIRECTION_PULL = 'pull'

    DIRECTION_CHOICES = [
        (DIRECTION_PUSH, 'Push to remote'),
        (DIRECTION_PULL, 'Pull from remote'),
    ]

    FLATTEN_NONE = 'none'
    FLATTEN_1 = 'flatten_1'
    FLATTEN_ALL = 'flatten_all'
    FLATTEN_CHOICES = [
        (FLATTEN_NONE,  'No flattening'),
        (FLATTEN_1,     'Flatten 1 level'),
        (FLATTEN_ALL,   'Flatten all levels'),
    ]

    RESOURCE_ALL = 'all'
    RESOURCE_IMAGE = 'image'
    RESOURCE_CHART = 'chart'
    RESOURCE_ARTIFACT = 'artifact'
    RESOURCE_CHOICES = [
        (RESOURCE_ALL,      'All'),
        (RESOURCE_IMAGE,    'Image'),
        (RESOURCE_CHART,    'Helm Chart'),
        (RESOURCE_ARTIFACT, 'OCI Artifact'),
    ]

    name = models.CharField(max_length=128)
    description = models.TextField(blank=True)
    remote = models.ForeignKey(RemoteRegistry, on_delete=models.CASCADE, related_name='replication_rules')
    direction = models.CharField(max_length=8, choices=DIRECTION_CHOICES, default=DIRECTION_PUSH)

    # ── Source filters ──────────────────────────────────────────────────────────
    source_filter = models.CharField(max_length=512, blank=True, help_text='Image name filter, e.g. library/**')
    tag_filter = models.CharField(max_length=255, blank=True, help_text='Tag filter, e.g. v* or latest')
    label_filter = models.CharField(max_length=512, blank=True, help_text='Comma-separated label matchers, e.g. env=prod')
    resource_type = models.CharField(max_length=16, choices=RESOURCE_CHOICES, default=RESOURCE_ALL)

    # ── Destination ─────────────────────────────────────────────────────────────
    destination_namespace = models.CharField(max_length=255, blank=True, help_text='Override namespace on destination')
    flatten_mode = models.CharField(max_length=16, choices=FLATTEN_CHOICES, default=FLATTEN_1)

    # ── Trigger ─────────────────────────────────────────────────────────────────
    trigger = models.CharField(max_length=16, choices=TRIGGER_CHOICES, default=TRIGGER_MANUAL)
    schedule = models.CharField(max_length=64, blank=True, help_text='Cron expression when trigger=scheduled')

    # ── Performance & behaviour ──────────────────────────────────────────────────
    bandwidth_limit_kb = models.IntegerField(default=-1, help_text='Bandwidth cap in Kbps; -1 = unlimited')
    override_existing = models.BooleanField(default=True, help_text='Overwrite artifacts that already exist on destination')
    single_active = models.BooleanField(default=False, help_text='Allow only one active execution at a time')
    delete_remote_on_local_delete = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)

    last_run_at = models.DateTimeField(null=True, blank=True)
    last_run_status = models.CharField(max_length=32, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f'{self.name} ({self.direction} → {self.remote.name})'


class ReplicationJob(models.Model):
    """One execution of a ReplicationRule — stores per-tag log lines and summary."""

    STATUS_PENDING  = 'pending'
    STATUS_RUNNING  = 'running'
    STATUS_SUCCESS  = 'success'
    STATUS_PARTIAL  = 'partial'
    STATUS_ERROR    = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_PARTIAL, 'Partial'),
        (STATUS_ERROR,   'Error'),
    ]

    rule        = models.ForeignKey(ReplicationRule, on_delete=models.CASCADE, related_name='jobs')
    status      = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    started_at  = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    copied      = models.IntegerField(default=0)
    errors      = models.IntegerField(default=0)
    log         = models.TextField(blank=True, help_text='Append-only log lines from the task')

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'job({self.rule.name}) {self.status}'

    def append_log(self, line: str) -> None:
        """Append a line to the log and save just that field."""
        import django.utils.timezone as tz
        ts = tz.now().strftime('%H:%M:%S')
        self.log = self.log + f'[{ts}] {line}\n'
        self.save(update_fields=['log'])


class SyncJob(models.Model):
    """One execution of run_registry_sync — tracks status and outcome."""

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_SUCCESS = 'success'
    STATUS_ERROR   = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_ERROR,   'Error'),
    ]

    status          = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    started_at      = models.DateTimeField(auto_now_add=True)
    finished_at     = models.DateTimeField(null=True, blank=True)
    repos_created   = models.IntegerField(default=0)
    tags_created    = models.IntegerField(default=0)
    error           = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'sync-job({self.pk}) {self.status}'


class GCJob(models.Model):
    """One execution of run_gc — records status, counts, blob GC output, and any error."""

    STATUS_PENDING  = 'pending'
    STATUS_RUNNING  = 'running'
    STATUS_SUCCESS  = 'success'
    STATUS_ERROR    = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_ERROR,   'Error'),
    ]

    status              = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    triggered_by        = models.CharField(max_length=16, default='schedule')  # 'schedule' or 'manual'
    started_at          = models.DateTimeField(auto_now_add=True)
    finished_at         = models.DateTimeField(null=True, blank=True)
    # Outcome counts
    orphans_deleted     = models.IntegerField(default=0)
    retention_deleted   = models.IntegerField(default=0)
    audit_deleted       = models.IntegerField(default=0)
    errors              = models.IntegerField(default=0)
    blob_gc_ok          = models.BooleanField(null=True)
    blob_gc_output      = models.TextField(blank=True)
    error               = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'gc-job({self.pk}) {self.status}'


class TrivyUpdateJob(models.Model):
    """One execution of run_trivy_db_update."""

    STATUS_PENDING  = 'pending'
    STATUS_RUNNING  = 'running'
    STATUS_SUCCESS  = 'success'
    STATUS_ERROR    = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_ERROR,   'Error'),
    ]

    status      = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    triggered_by = models.CharField(max_length=16, default='schedule')  # 'schedule' or 'manual'
    started_at  = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error       = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'trivy-update-job({self.pk}) {self.status}'


class ProjectPolicy(models.Model):
    """Per-project security, SBOM, and tag policies. One row per project (get_or_create pk=project)."""

    project = models.OneToOneField(Project, on_delete=models.CASCADE, related_name='policy')

    # ── SBOM ──────────────────────────────────────────────────────────────────
    sbom_enabled = models.BooleanField(
        default=False,
        help_text='Auto-generate SBOM (Syft) on every push',
    )

    # ── Content Trust / Signature enforcement ─────────────────────────────────
    cosign_required = models.BooleanField(
        default=False,
        help_text='Block pulls of images without a valid Cosign signature',
    )
    notation_required = models.BooleanField(
        default=False,
        help_text='Block pulls of images without a valid Notation (CNCF) signature',
    )

    # ── Vulnerability scanning ─────────────────────────────────────────────────
    scanning_enabled = models.BooleanField(
        default=True,
        help_text='Automatically run Trivy on every pushed image',
    )

    # ── Automated vulnerability re-scanning ────────────────────────────────────
    vuln_rescan_enabled = models.BooleanField(
        default=True,
        help_text='Periodically re-scan images for new CVEs (only meaningful when scanning_enabled=True)',
    )
    vuln_rescan_interval_days = models.PositiveIntegerField(
        default=7,
        help_text='How many days between automated vulnerability re-scans (1, 7, 14, or 30)',
    )

    # ── Active-inventory re-scanning ───────────────────────────────────────────
    vuln_rescan_active_only = models.BooleanField(
        default=False,
        help_text=(
            'When True, automated re-scans are skipped for tags that have had no '
            'push or pull activity within vuln_rescan_active_days days.'
        ),
    )
    vuln_rescan_active_days = models.PositiveIntegerField(
        default=90,
        help_text=(
            'Tags with no push/pull activity within this many days are considered '
            'stale and excluded from automated re-scans when vuln_rescan_active_only=True.'
        ),
    )

    # ── Secret scanning ────────────────────────────────────────────────────────
    secret_scanning_enabled = models.BooleanField(
        default=False,
        help_text='Automatically run Trivy secret scanning on every pushed image',
    )

    # ── Misconfiguration scanning ──────────────────────────────────────────────
    misconfig_scanning_enabled = models.BooleanField(
        default=False,
        help_text='Automatically run Trivy misconfiguration scanning on every pushed image',
    )

    # ── Vulnerability prevention ───────────────────────────────────────────────
    prevent_vulnerable_images = models.BooleanField(
        default=False,
        help_text='Block pulls when the image violates the vuln_block_rules thresholds',
    )
    # Per-severity maximum allowed counts.
    # null = not enforced for that severity; 0 = zero tolerance.
    # Example: {"critical": 0, "high": 5, "medium": null, "low": null}
    vuln_block_rules = models.JSONField(
        default=dict,
        blank=True,
        help_text='Per-severity max counts; null = unenforced, 0 = zero tolerance',
    )

    # ── Secret prevention ─────────────────────────────────────────────────────
    prevent_secret_images = models.BooleanField(
        default=False,
        help_text='Block pulls when the image has secrets detected above the threshold',
    )
    # Maximum allowed secrets count before a pull is blocked; null = not enforced.
    secret_block_threshold = models.IntegerField(
        null=True,
        blank=True,
        default=None,
        help_text='Max allowed secrets count (null = unenforced, 0 = zero tolerance)',
    )

    # ── Misconfiguration prevention ────────────────────────────────────────────
    prevent_misconfig_images = models.BooleanField(
        default=False,
        help_text='Block pulls when the image has FAIL misconfigurations above the threshold',
    )
    # Maximum allowed FAIL misconfig count before a pull is blocked; null = not enforced.
    misconfig_fail_threshold = models.IntegerField(
        null=True,
        blank=True,
        default=None,
        help_text='Max allowed FAIL misconfig count (null = unenforced, 0 = zero tolerance)',
    )

    # ── Tag immutability ──────────────────────────────────────────────────────
    tag_immutability = models.BooleanField(
        default=False,
        help_text='Prevent existing tags from being overwritten',
    )

    # ── Tag retention rules (stored as JSON array of rule objects) ────────────
    # Each rule: { "match": "glob-pattern", "keep_count": int|null, "keep_days": int|null }
    tag_retention_rules = models.JSONField(
        default=list,
        blank=True,
        help_text='Ordered list of tag retention rules evaluated on GC runs',
    )

    class Meta:
        verbose_name = 'Project Policy'
        verbose_name_plural = 'Project Policies'

    def __str__(self):
        return f'policy({self.project.name})'


class TagSignatureStatus(models.Model):
    """Signature verification result for a tag — one row per tag, updated in place."""

    RESULT_SIGNED = 'signed'
    RESULT_NOT_SIGNED = 'not_signed'
    RESULT_FAILED = 'failed'       # artifact present but verification error
    RESULT_UNKNOWN = 'unknown'     # not yet checked
    RESULT_NOT_AVAILABLE = 'not_available'  # tool not installed

    RESULT_CHOICES = [
        (RESULT_SIGNED,        'Signed'),
        (RESULT_NOT_SIGNED,    'Not signed'),
        (RESULT_FAILED,        'Verification failed'),
        (RESULT_UNKNOWN,       'Unknown'),
        (RESULT_NOT_AVAILABLE, 'Not available'),
    ]

    tag = models.OneToOneField(Tag, on_delete=models.CASCADE, related_name='signature_status')
    cosign  = models.CharField(max_length=32, choices=RESULT_CHOICES, default=RESULT_UNKNOWN)
    notation = models.CharField(max_length=32, choices=RESULT_CHOICES, default=RESULT_NOT_AVAILABLE)
    cosign_output   = models.TextField(blank=True, help_text='stdout/stderr from last cosign run')
    notation_output = models.TextField(blank=True, help_text='stdout/stderr from last notation run')
    checked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Tag Signature Status'

    def __str__(self):
        return f'sig({self.tag}) cosign={self.cosign} notation={self.notation}'


class VulnerabilityScan(models.Model):
    """Trivy scan result for a specific tag."""

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_FINISHED = 'finished'
    STATUS_ERROR = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_FINISHED, 'Finished'),
        (STATUS_ERROR, 'Error'),
    ]

    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='scans')
    scanner = models.CharField(max_length=64, default='trivy')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True, db_index=True)
    summary = models.JSONField(
        default=dict,
        help_text='{"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "unknown": 0}'
    )
    report = models.JSONField(default=list, help_text='Full CVE list from Trivy')

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'scan({self.tag}) {self.status}'


class SecretScan(models.Model):
    """Trivy secret scan result for a specific tag."""

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_FINISHED = 'finished'
    STATUS_ERROR = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_FINISHED, 'Finished'),
        (STATUS_ERROR, 'Error'),
    ]

    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='secret_scans')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Total count of secrets found
    total = models.IntegerField(default=0)
    # Full findings list: [{rule_id, category, severity, title, target, match, ...}]
    report = models.JSONField(default=list)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'secret_scan({self.tag}) {self.status}'


class MisconfigScan(models.Model):
    """Trivy misconfiguration scan result for a specific tag."""

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_FINISHED = 'finished'
    STATUS_ERROR = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_FINISHED, 'Finished'),
        (STATUS_ERROR, 'Error'),
    ]

    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='misconfig_scans')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Summary: {"FAIL": 0, "WARN": 0, "PASS": 0}
    summary = models.JSONField(default=dict)
    # Full findings list: [{id, avd_id, title, description, severity, status, resolution, ...}]
    report = models.JSONField(default=list)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f'misconfig_scan({self.tag}) {self.status}'


class SBOMReport(models.Model):
    """SPDX SBOM generated by Syft for a specific tag."""

    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_FINISHED = 'finished'
    STATUS_ERROR = 'error'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_FINISHED, 'Finished'),
        (STATUS_ERROR, 'Error'),
    ]

    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='sbom_reports')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Full SPDX JSON document
    report = models.JSONField(default=dict)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'sbom({self.tag}) {self.status}'


class VulnAllowlistEntry(models.Model):
    """
    A suppressed CVE / vulnerability ID.

    Scope is determined by which FK is set:
      - project only  → project-wide suppression (applies to all tags in the project)
      - project + tag → tag-specific suppression (overrides for that image only)

    `cve_id` stores the canonical identifier, e.g. "CVE-2024-1234" or a Trivy
    AVD ID like "AVD-GO-0001".  `reason` is a free-text note shown in the UI.
    `expires_at` is optional; expired entries are ignored by the filter but kept
    for audit purposes.
    """

    project    = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='vuln_allowlist')
    tag        = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='vuln_allowlist',
                                   null=True, blank=True)
    cve_id     = models.CharField(max_length=128)
    reason     = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    added_by   = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['cve_id']
        # Prevent duplicate entries for the same scope
        unique_together = [('project', 'tag', 'cve_id')]

    def __str__(self):
        scope = f'{self.tag}' if self.tag_id else 'project-wide'
        return f'allowlist({self.project.name}/{scope}: {self.cve_id})'

    @property
    def is_expired(self):
        from django.utils import timezone
        return self.expires_at is not None and self.expires_at < timezone.now()


class SecretAllowlistEntry(models.Model):
    """
    A suppressed secret finding.  `tag=None` means project-wide (applies to all images in the
    project).  When `tag` is set the suppression is image-specific only.

    `rule_id` is the Trivy rule identifier, e.g. "aws-access-key-id".
    `reason` is a free-text note shown in the UI.
    `expires_at` is optional; expired entries are ignored by the filter but kept for audit.
    """

    project    = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='secret_allowlist', null=True, blank=True)
    tag        = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='secret_allowlist', null=True, blank=True)
    rule_id    = models.CharField(max_length=256)
    reason     = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    added_by   = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['rule_id']
        unique_together = [('project', 'tag', 'rule_id')]

    def __str__(self):
        return f'secret-allowlist({self.project or self.tag}: {self.rule_id})'

    @property
    def is_expired(self):
        from django.utils import timezone
        return self.expires_at is not None and self.expires_at < timezone.now()


class MisconfigAllowlistEntry(models.Model):
    """
    A suppressed misconfiguration finding.  `tag=None` means project-wide (applies to all images
    in the project).  When `tag` is set the suppression is image-specific only.

    `check_id` is the Trivy check identifier, e.g. "AVD-DS-0002" or "DS002".
    Trivy findings carry both `id` and `avd_id`; we store whichever is more canonical
    (the caller normalises to `avd_id` when present, else `id`).
    `reason` is a free-text note shown in the UI.
    `expires_at` is optional.
    """

    project    = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='misconfig_allowlist', null=True, blank=True)
    tag        = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name='misconfig_allowlist', null=True, blank=True)
    check_id   = models.CharField(max_length=256)
    reason     = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    added_by   = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['check_id']
        unique_together = [('project', 'tag', 'check_id')]

    def __str__(self):
        return f'misconfig-allowlist({self.project or self.tag}: {self.check_id})'

    @property
    def is_expired(self):
        from django.utils import timezone
        return self.expires_at is not None and self.expires_at < timezone.now()
