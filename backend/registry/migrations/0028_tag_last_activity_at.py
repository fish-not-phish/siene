"""
0028 — Add Tag.last_activity_at.

Tracks the timestamp of the most recent real push or pull event for a tag.
Unlike pushed_at (auto_now=True, updated on every model save), this field is
only set explicitly in the webhook handler (push) and token-issue handler (pull),
so internal saves by scan workers never bump it.

Indexed so run_rescan_stale can efficiently filter by activity date.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0027_scan_auditlog_indexes'),
    ]

    operations = [
        migrations.AddField(
            model_name='tag',
            name='last_activity_at',
            field=models.DateTimeField(
                null=True,
                blank=True,
                db_index=True,
                help_text='Timestamp of most recent push or pull event for this tag.',
            ),
        ),
    ]
