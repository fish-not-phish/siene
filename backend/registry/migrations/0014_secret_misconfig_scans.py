from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0013_alter_remoteregistry_password_enc'),
    ]

    operations = [
        # Add secret_scanning_enabled + misconfig_scanning_enabled to ProjectPolicy
        migrations.AddField(
            model_name='projectpolicy',
            name='secret_scanning_enabled',
            field=models.BooleanField(
                default=False,
                help_text='Automatically run Trivy secret scanning on every pushed image',
            ),
        ),
        migrations.AddField(
            model_name='projectpolicy',
            name='misconfig_scanning_enabled',
            field=models.BooleanField(
                default=False,
                help_text='Automatically run Trivy misconfiguration scanning on every pushed image',
            ),
        ),
        # SecretScan model
        migrations.CreateModel(
            name='SecretScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('finished', 'Finished'),
                        ('error', 'Error'),
                    ],
                    default='pending',
                    max_length=32,
                )),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('total', models.IntegerField(default=0)),
                ('report', models.JSONField(default=list)),
                ('tag', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='secret_scans',
                    to='registry.tag',
                )),
            ],
            options={
                'ordering': ['-started_at'],
            },
        ),
        # MisconfigScan model
        migrations.CreateModel(
            name='MisconfigScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('finished', 'Finished'),
                        ('error', 'Error'),
                    ],
                    default='pending',
                    max_length=32,
                )),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('summary', models.JSONField(default=dict)),
                ('report', models.JSONField(default=list)),
                ('tag', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='misconfig_scans',
                    to='registry.tag',
                )),
            ],
            options={
                'ordering': ['-started_at'],
            },
        ),
    ]
