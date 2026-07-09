"""
0029 — Add active-inventory re-scan fields to ProjectPolicy.

vuln_rescan_active_only: when True, automated re-scans skip tags that have had
no push or pull activity within vuln_rescan_active_days days.

vuln_rescan_active_days: the staleness window in days (default 90).
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0028_tag_last_activity_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='projectpolicy',
            name='vuln_rescan_active_only',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'When True, automated re-scans are skipped for tags that have had no '
                    'push or pull activity within vuln_rescan_active_days days.'
                ),
            ),
        ),
        migrations.AddField(
            model_name='projectpolicy',
            name='vuln_rescan_active_days',
            field=models.PositiveIntegerField(
                default=90,
                help_text=(
                    'Tags with no push/pull activity within this many days are considered '
                    'stale and excluded from automated re-scans when vuln_rescan_active_only=True.'
                ),
            ),
        ),
    ]
