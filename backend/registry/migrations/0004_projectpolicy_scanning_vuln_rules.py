from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0003_projectpolicy'),
    ]

    operations = [
        # Add scanning_enabled
        migrations.AddField(
            model_name='projectpolicy',
            name='scanning_enabled',
            field=models.BooleanField(
                default=True,
                help_text='Automatically run Trivy on every pushed image',
            ),
        ),
        # Add vuln_block_rules (replaces vulnerability_severity_threshold)
        migrations.AddField(
            model_name='projectpolicy',
            name='vuln_block_rules',
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text='Per-severity max counts; null = unenforced, 0 = zero tolerance',
            ),
        ),
        # Remove the old single-threshold field
        migrations.RemoveField(
            model_name='projectpolicy',
            name='vulnerability_severity_threshold',
        ),
    ]
