from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_gc_schedule'),
    ]

    operations = [
        migrations.AddField(
            model_name='sitesettings',
            name='audit_log_retention_days',
            field=models.PositiveIntegerField(
                default=365,
                help_text='Delete audit log entries older than this many days. 0 = keep forever.',
            ),
        ),
    ]
