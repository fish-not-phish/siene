from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0015_vuln_allowlist'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SecretAllowlistEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rule_id', models.CharField(max_length=256)),
                ('reason', models.TextField(blank=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('tag', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='secret_allowlist', to='registry.tag')),
                ('added_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['rule_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='secretallowlistentry',
            constraint=models.UniqueConstraint(fields=('tag', 'rule_id'), name='unique_secret_allowlist_entry'),
        ),
        migrations.CreateModel(
            name='MisconfigAllowlistEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('check_id', models.CharField(max_length=256)),
                ('reason', models.TextField(blank=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('tag', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='misconfig_allowlist', to='registry.tag')),
                ('added_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['check_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='misconfigallowlistentry',
            constraint=models.UniqueConstraint(fields=('tag', 'check_id'), name='unique_misconfig_allowlist_entry'),
        ),
    ]
