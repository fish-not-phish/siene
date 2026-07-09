import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0006_replicationrule_extended_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='SBOMReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('finished', 'Finished'), ('error', 'Error')], default='pending', max_length=32)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('report', models.JSONField(default=dict)),
                ('tag', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sbom_reports', to='registry.tag')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
