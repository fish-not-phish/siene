from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_audit_log_retention'),
    ]

    operations = [
        migrations.AddField(
            model_name='sitesettings',
            name='trivy_db_update_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='sitesettings',
            name='trivy_db_update_interval_hours',
            field=models.PositiveIntegerField(default=12),
        ),
        migrations.AddField(
            model_name='sitesettings',
            name='trivy_db_last_updated_at',
            field=models.DateTimeField(null=True, blank=True),
        ),
    ]
