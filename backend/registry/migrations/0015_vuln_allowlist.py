from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0014_secret_misconfig_scans'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='VulnAllowlistEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cve_id', models.CharField(max_length=128)),
                ('reason', models.TextField(blank=True)),
                ('expires_at', models.DateTimeField(null=True, blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='vuln_allowlist',
                    to='registry.project',
                )),
                ('tag', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='vuln_allowlist',
                    to='registry.tag',
                )),
                ('added_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['cve_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='vulnallowlistentry',
            constraint=models.UniqueConstraint(
                fields=['project', 'tag', 'cve_id'],
                name='unique_allowlist_entry',
            ),
        ),
    ]
