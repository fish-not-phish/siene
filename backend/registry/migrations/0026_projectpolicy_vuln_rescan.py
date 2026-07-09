"""
0026 — add vuln_rescan_enabled and vuln_rescan_interval_days to ProjectPolicy.

Automated vulnerability re-scans now respect a per-project on/off toggle and a
configurable interval (default 7 days). The old hard-coded 24-hour cutoff in
run_rescan_stale is replaced by this interval.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0025_log_retention_and_trivy_job'),
    ]

    operations = [
        migrations.AddField(
            model_name='projectpolicy',
            name='vuln_rescan_enabled',
            field=models.BooleanField(
                default=True,
                help_text='Periodically re-scan images for new CVEs (only meaningful when scanning_enabled=True)',
            ),
        ),
        migrations.AddField(
            model_name='projectpolicy',
            name='vuln_rescan_interval_days',
            field=models.PositiveIntegerField(
                default=7,
                help_text='How many days between automated vulnerability re-scans (1, 7, 14, or 30)',
            ),
        ),
    ]
