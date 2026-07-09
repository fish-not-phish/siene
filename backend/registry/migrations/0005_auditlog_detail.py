from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0004_projectpolicy_scanning_vuln_rules'),
    ]

    operations = [
        migrations.AddField(
            model_name='auditlog',
            name='detail',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text='Structured change data — fields vary by resource type',
            ),
        ),
    ]
