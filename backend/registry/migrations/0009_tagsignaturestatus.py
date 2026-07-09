from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0008_tag_labels'),
    ]

    operations = [
        migrations.CreateModel(
            name='TagSignatureStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cosign', models.CharField(
                    choices=[
                        ('signed', 'Signed'),
                        ('not_signed', 'Not signed'),
                        ('failed', 'Verification failed'),
                        ('unknown', 'Unknown'),
                        ('not_available', 'Not available'),
                    ],
                    default='unknown',
                    max_length=32,
                )),
                ('notation', models.CharField(
                    choices=[
                        ('signed', 'Signed'),
                        ('not_signed', 'Not signed'),
                        ('failed', 'Verification failed'),
                        ('unknown', 'Unknown'),
                        ('not_available', 'Not available'),
                    ],
                    default='not_available',
                    max_length=32,
                )),
                ('cosign_output', models.TextField(blank=True, help_text='stdout/stderr from last cosign run')),
                ('notation_output', models.TextField(blank=True, help_text='stdout/stderr from last notation run')),
                ('checked_at', models.DateTimeField(blank=True, null=True)),
                ('tag', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='signature_status',
                    to='registry.tag',
                )),
            ],
            options={
                'verbose_name': 'Tag Signature Status',
            },
        ),
    ]
