"""
0027 — Add indexes on frequently-filtered columns.

VulnerabilityScan / SecretScan / MisconfigScan:
  - status       — filtered by _scan_already_inflight(), pull-prevention, run_rescan_stale
  - finished_at  — ordered/filtered by run_rescan_stale and tag detail API

AuditLog:
  - timestamp    — ordered and range-filtered by audit log endpoints and GC pruning
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0026_projectpolicy_vuln_rescan'),
    ]

    operations = [
        # VulnerabilityScan
        migrations.AlterField(
            model_name='vulnerabilityscan',
            name='status',
            field=models.CharField(
                max_length=32,
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('finished', 'Finished'),
                    ('error', 'Error'),
                ],
                default='pending',
                db_index=True,
            ),
        ),
        migrations.AlterField(
            model_name='vulnerabilityscan',
            name='finished_at',
            field=models.DateTimeField(null=True, blank=True, db_index=True),
        ),

        # SecretScan
        migrations.AlterField(
            model_name='secretscan',
            name='status',
            field=models.CharField(
                max_length=32,
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('finished', 'Finished'),
                    ('error', 'Error'),
                ],
                default='pending',
                db_index=True,
            ),
        ),
        migrations.AlterField(
            model_name='secretscan',
            name='finished_at',
            field=models.DateTimeField(null=True, blank=True, db_index=True),
        ),

        # MisconfigScan
        migrations.AlterField(
            model_name='misconfigscan',
            name='status',
            field=models.CharField(
                max_length=32,
                choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('finished', 'Finished'),
                    ('error', 'Error'),
                ],
                default='pending',
                db_index=True,
            ),
        ),
        migrations.AlterField(
            model_name='misconfigscan',
            name='finished_at',
            field=models.DateTimeField(null=True, blank=True, db_index=True),
        ),

        # AuditLog
        migrations.AlterField(
            model_name='auditlog',
            name='timestamp',
            field=models.DateTimeField(auto_now_add=True, db_index=True),
        ),
    ]
