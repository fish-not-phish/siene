"""
0017 — add project-wide scope to SecretAllowlistEntry and MisconfigAllowlistEntry.

Changes:
  - SecretAllowlistEntry.tag  becomes nullable (null=True, blank=True)
  - SecretAllowlistEntry.project FK added (nullable for existing rows; backfilled below)
  - unique_together changed from (tag, rule_id) → (project, tag, rule_id)
  - Same changes mirrored on MisconfigAllowlistEntry (check_id instead of rule_id)

Data migration: for every existing tag-scoped row, set project = tag.repository.project
so the new unique_together constraint is satisfied.

NOTE: RunPython must come after *both* AddField operations so the historical model
state for both tables already has the project column.
"""

from django.db import migrations, models
import django.db.models.deletion


def backfill_project(apps, schema_editor):
    SecretAllowlistEntry = apps.get_model('registry', 'SecretAllowlistEntry')
    MisconfigAllowlistEntry = apps.get_model('registry', 'MisconfigAllowlistEntry')

    for entry in SecretAllowlistEntry.objects.select_related('tag__repository__project').filter(project_id__isnull=True):
        if entry.tag_id:
            entry.project = entry.tag.repository.project
            entry.save(update_fields=['project'])

    for entry in MisconfigAllowlistEntry.objects.select_related('tag__repository__project').filter(project_id__isnull=True):
        if entry.tag_id:
            entry.project = entry.tag.repository.project
            entry.save(update_fields=['project'])


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0016_secret_misconfig_allowlists'),
    ]

    operations = [
        # ── SecretAllowlistEntry ──────────────────────────────────────────────

        # 1. Drop the old unique_together so we can alter the fields
        migrations.AlterUniqueTogether(
            name='secretallowlistentry',
            unique_together=set(),
        ),

        # 2. Make tag nullable
        migrations.AlterField(
            model_name='secretallowlistentry',
            name='tag',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='secret_allowlist',
                to='registry.tag',
            ),
        ),

        # 3. Add project FK (nullable so existing rows don't fail immediately)
        migrations.AddField(
            model_name='secretallowlistentry',
            name='project',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='secret_allowlist',
                to='registry.project',
            ),
        ),

        # ── MisconfigAllowlistEntry ───────────────────────────────────────────

        migrations.AlterUniqueTogether(
            name='misconfigallowlistentry',
            unique_together=set(),
        ),

        migrations.AlterField(
            model_name='misconfigallowlistentry',
            name='tag',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='misconfig_allowlist',
                to='registry.tag',
            ),
        ),

        migrations.AddField(
            model_name='misconfigallowlistentry',
            name='project',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='misconfig_allowlist',
                to='registry.project',
            ),
        ),

        # 4. Backfill project on existing rows — runs after BOTH AddFields above
        #    so the historical state for both models already has the project column.
        migrations.RunPython(backfill_project, migrations.RunPython.noop),

        # 5. Restore unique_together with project included (both tables)
        migrations.AlterUniqueTogether(
            name='secretallowlistentry',
            unique_together={('project', 'tag', 'rule_id')},
        ),

        migrations.AlterUniqueTogether(
            name='misconfigallowlistentry',
            unique_together={('project', 'tag', 'check_id')},
        ),
    ]
