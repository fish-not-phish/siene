from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0002_labels_remotes_replications'),
    ]

    operations = [
        migrations.CreateModel(
            name='ProjectPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sbom_enabled', models.BooleanField(default=False, help_text='Auto-generate SBOM (Syft) on every push')),
                ('cosign_required', models.BooleanField(default=False, help_text='Block pulls of images without a valid Cosign signature')),
                ('notation_required', models.BooleanField(default=False, help_text='Block pulls of images without a valid Notation (CNCF) signature')),
                ('prevent_vulnerable_images', models.BooleanField(default=False, help_text='Block pulls of images with vulnerabilities at or above the threshold')),
                ('vulnerability_severity_threshold', models.CharField(
                    choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low')],
                    default='critical',
                    help_text='Minimum severity that triggers a pull block',
                    max_length=16,
                )),
                ('tag_immutability', models.BooleanField(default=False, help_text='Prevent existing tags from being overwritten')),
                ('tag_retention_rules', models.JSONField(blank=True, default=list, help_text='Ordered list of tag retention rules evaluated on GC runs')),
                ('project', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='policy',
                    to='registry.project',
                )),
            ],
            options={
                'verbose_name': 'Project Policy',
                'verbose_name_plural': 'Project Policies',
            },
        ),
    ]
