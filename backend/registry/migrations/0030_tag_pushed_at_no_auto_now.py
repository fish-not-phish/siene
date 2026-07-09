"""
0030 — Remove auto_now from Tag.pushed_at.

auto_now=True caused pushed_at to be bumped on every model.save(), meaning
scan workers, SBOM tasks, and signature checks would silently overwrite the
real push timestamp with the current time.  Changing to a plain DateTimeField
means the value is now set explicitly only when a real push event is processed.

Existing rows already have a pushed_at value (set by auto_now on every save).
Those values may be slightly wrong (they reflect the last internal save, not
the original push), but that is a pre-existing condition — this migration does
not attempt to back-fill correct timestamps because we have no reliable source
of truth for old rows.

The schema change itself is a no-op on PostgreSQL (just removes the auto_now
behaviour which lives in Python, not in the DB column).
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0029_projectpolicy_active_rescan'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tag',
            name='pushed_at',
            field=models.DateTimeField(
                help_text='Timestamp of the most recent push event for this tag. '
                          'Set explicitly on push only — never auto_now.',
            ),
        ),
    ]
