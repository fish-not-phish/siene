import secrets
import hashlib
from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return f"Profile for {self.user.username if self.user else 'Unknown'}"


class PersonalAccessToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='personal_access_tokens')
    name = models.CharField(max_length=128)
    token_hash = models.CharField(max_length=64, unique=True)
    prefix = models.CharField(max_length=8)  # first 8 chars shown in UI
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} / {self.name}"

    @classmethod
    def create_token(cls, user, name, expires_at=None):
        """Generate a new PAT. Returns (instance, plaintext_token)."""
        raw = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:8]
        instance = cls.objects.create(
            user=user,
            name=name,
            token_hash=token_hash,
            prefix=prefix,
            expires_at=expires_at,
        )
        return instance, raw


class SiteSettings(models.Model):
    allow_registration = models.BooleanField(default=True)
    oidc_enabled = models.BooleanField(default=False)
    oidc_provider_type = models.CharField(max_length=64, blank=True, default='')
    oidc_client_id = models.CharField(max_length=255, blank=True, default='')
    oidc_client_secret = models.CharField(max_length=255, blank=True, default='')
    oidc_server_url = models.CharField(max_length=500, blank=True, default='')

    # Garbage collection schedule
    GC_SCHEDULE_HOURLY = 'hourly'
    GC_SCHEDULE_EVERY_N_HOURS = 'every_n_hours'
    GC_SCHEDULE_DAILY = 'daily'
    GC_SCHEDULE_WEEKLY = 'weekly'
    GC_SCHEDULE_MONTHLY = 'monthly'
    GC_SCHEDULE_CHOICES = [
        (GC_SCHEDULE_HOURLY, 'Every hour'),
        (GC_SCHEDULE_EVERY_N_HOURS, 'Every N hours'),
        (GC_SCHEDULE_DAILY, 'Daily'),
        (GC_SCHEDULE_WEEKLY, 'Weekly'),
        (GC_SCHEDULE_MONTHLY, 'Monthly'),
    ]

    gc_enabled = models.BooleanField(default=False)
    gc_schedule_type = models.CharField(
        max_length=20, choices=GC_SCHEDULE_CHOICES, default=GC_SCHEDULE_DAILY,
    )
    gc_interval_hours = models.PositiveIntegerField(default=24)
    # HH:MM in the server's local timezone — used for daily / weekly / monthly
    gc_schedule_time = models.CharField(max_length=5, default='02:00')
    # 0=Monday … 6=Sunday — used for weekly
    gc_schedule_day_of_week = models.PositiveSmallIntegerField(default=0)
    # 1–28 — used for monthly
    gc_schedule_day_of_month = models.PositiveSmallIntegerField(default=1)
    gc_last_run_at = models.DateTimeField(null=True, blank=True)

    # Log retention
    audit_log_retention_days = models.PositiveIntegerField(
        default=365,
        help_text='Delete audit log entries older than this many days. 0 = keep forever.',
    )
    job_log_retention_days = models.PositiveIntegerField(
        default=30,
        help_text='Delete GC, sync, replication, and Trivy update job rows older than this many days. 0 = keep forever.',
    )

    # Vulnerability re-scan batch size
    # Controls how many scan tasks are enqueued per Beat tick (every 6 hours).
    # Prevents flooding the single-concurrency scans queue with more work than
    # it can drain before the next tick.  Remaining tags are picked up on the
    # next tick, oldest-scanned-first, so no tag is permanently skipped — just
    # deferred.  Increase this if your registry is large and you have confirmed
    # the scan worker keeps up.
    rescan_batch_size = models.PositiveIntegerField(
        default=200,
        help_text=(
            'Maximum vulnerability re-scan tasks enqueued per 6-hour Beat tick. '
            'Increase for larger registries; reduce if the scan queue backs up.'
        ),
    )

    # Trivy vulnerability DB auto-update
    trivy_db_update_enabled = models.BooleanField(default=False)
    trivy_db_update_interval_hours = models.PositiveIntegerField(default=12)
    trivy_db_last_updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Site Settings'

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj