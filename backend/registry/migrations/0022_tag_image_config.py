from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0021_fix_projectpolicy_schema'),
    ]

    operations = [
        migrations.AddField(
            model_name='tag',
            name='image_config',
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
