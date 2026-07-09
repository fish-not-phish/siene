"""
0009 — Add SiteSettings.rescan_batch_size.

Controls how many vulnerability re-scan tasks run_rescan_stale enqueues per
6-hour Beat tick, preventing the single-concurrency scans queue from being
flooded with more work than it can drain before the next tick fires.
Default 200 matches the previously hardcoded constant.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_log_retention_and_trivy_job'),
    ]

    operations = [
        migrations.AddField(
            model_name='sitesettings',
            name='rescan_batch_size',
            field=models.PositiveIntegerField(
                default=200,
                help_text=(
                    'Maximum vulnerability re-scan tasks enqueued per 6-hour Beat tick. '
                    'Increase for larger registries; reduce if the scan queue backs up.'
                ),
            ),
        ),
    ]
