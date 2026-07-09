from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0022_tag_image_config'),
    ]

    operations = [
        migrations.CreateModel(
            name='SyncJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('success', 'Success'),
                        ('error', 'Error'),
                    ],
                    default='pending',
                    max_length=16,
                )),
                ('started_at', models.DateTimeField(auto_now_add=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('repos_created', models.IntegerField(default=0)),
                ('tags_created', models.IntegerField(default=0)),
                ('error', models.TextField(blank=True)),
            ],
            options={
                'ordering': ['-started_at'],
            },
        ),
    ]
