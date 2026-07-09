"""
0031 — Add multi-arch manifest index fields to Tag.

Adds four new fields that enable Option A per-platform child tag storage:

  is_index       BooleanField  — marks the manifest list / OCI index tag row
  index_manifest JSONField     — raw OCI index JSON (populated when is_index=True)
  parent_tag     FK(self)      — links a per-platform child tag back to its index tag
  platform       CharField     — e.g. "linux/amd64" / "linux/arm64/v8" (child tags only)

All fields default to False / {} / NULL / '' so existing single-arch tag rows
are completely unaffected.  No data migration is needed.
"""

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0030_tag_pushed_at_no_auto_now'),
    ]

    operations = [
        migrations.AddField(
            model_name='tag',
            name='is_index',
            field=models.BooleanField(
                default=False,
                db_index=True,
                help_text='True if this tag points to a multi-arch OCI index / manifest list.',
            ),
        ),
        migrations.AddField(
            model_name='tag',
            name='index_manifest',
            field=models.JSONField(
                default=dict,
                blank=True,
                help_text='Full OCI index / manifest list JSON.  Populated only when is_index=True.',
            ),
        ),
        migrations.AddField(
            model_name='tag',
            name='parent_tag',
            field=models.ForeignKey(
                to='registry.tag',
                on_delete=django.db.models.deletion.CASCADE,
                null=True,
                blank=True,
                related_name='platform_children',
                help_text='For per-platform child tags: the index tag this child belongs to.',
            ),
        ),
        migrations.AddField(
            model_name='tag',
            name='platform',
            field=models.CharField(
                max_length=64,
                blank=True,
                help_text='Platform string for per-platform child tags (e.g. "linux/amd64").',
            ),
        ),
    ]
