"""
0020 — Drop the named UniqueConstraint added by 0015 for VulnAllowlistEntry.

0015 created:
  UniqueConstraint(fields=('project', 'tag', 'cve_id'), name='unique_allowlist_entry')

The model also declares unique_together = [('project', 'tag', 'cve_id')], which
creates a second implicit unique index on the same columns.  Both constraints
coexist in the DB.  0019 fixed the same issue for SecretAllowlistEntry and
MisconfigAllowlistEntry — this migration completes the cleanup for VulnAllowlistEntry.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0019_drop_stale_allowlist_constraints'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='vulnallowlistentry',
            name='unique_allowlist_entry',
        ),
    ]
