"""
0018 — add secret and misconfig pull-prevention fields to ProjectPolicy.

New fields:
  - prevent_secret_images    (BooleanField, default=False)
  - secret_block_threshold   (IntegerField, null=True, default=None)
  - prevent_misconfig_images (BooleanField, default=False)
  - misconfig_fail_threshold (IntegerField, null=True, default=None)
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0017_secret_misconfig_allowlists_project_scope'),
    ]

    operations = [
        migrations.AddField(
            model_name='projectpolicy',
            name='prevent_secret_images',
            field=models.BooleanField(
                default=False,
                help_text='Block pulls when the image has secrets detected above the threshold',
            ),
        ),
        migrations.AddField(
            model_name='projectpolicy',
            name='secret_block_threshold',
            field=models.IntegerField(
                null=True,
                blank=True,
                default=None,
                help_text='Max allowed secrets count (null = unenforced, 0 = zero tolerance)',
            ),
        ),
        migrations.AddField(
            model_name='projectpolicy',
            name='prevent_misconfig_images',
            field=models.BooleanField(
                default=False,
                help_text='Block pulls when the image has FAIL misconfigurations above the threshold',
            ),
        ),
        migrations.AddField(
            model_name='projectpolicy',
            name='misconfig_fail_threshold',
            field=models.IntegerField(
                null=True,
                blank=True,
                default=None,
                help_text='Max allowed FAIL misconfig count (null = unenforced, 0 = zero tolerance)',
            ),
        ),
    ]
