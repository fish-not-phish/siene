"""
0019 — Drop the named UniqueConstraints added by 0016 that were never removed by 0017.

0016 created:
  UniqueConstraint(fields=('tag', 'rule_id'),   name='unique_secret_allowlist_entry')
  UniqueConstraint(fields=('tag', 'check_id'),  name='unique_misconfig_allowlist_entry')

0017 used AlterUniqueTogether (which manages the implicit unique_together index, not
named UniqueConstraints), so those two constraints were left behind in the DB alongside
the new unique_together=('project', 'tag', 'rule_id'/'check_id').

This migration drops the stale constraints so the DB schema matches the model.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0018_projectpolicy_secret_misconfig_prevention'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='secretallowlistentry',
            name='unique_secret_allowlist_entry',
        ),
        migrations.RemoveConstraint(
            model_name='misconfigallowlistentry',
            name='unique_misconfig_allowlist_entry',
        ),
    ]
