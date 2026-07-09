from django.db import migrations


class Migration(migrations.Migration):
    """
    Remove 'acr-alibaba' from RemoteRegistry.registry_type choices.
    The constant TYPE_ACR_ALIBABA is kept on the model for backward
    compatibility with any existing rows, but it is no longer offered
    in the UI or API choices list.
    """

    dependencies = [
        ('registry', '0009_tagsignaturestatus'),
    ]

    operations = [
        migrations.AlterField(
            model_name='remoteregistry',
            name='registry_type',
            field=__import__('django.db.models', fromlist=['CharField']).CharField(
                choices=[
                    ('docker-hub',      'Docker Hub'),
                    ('docker-registry', 'Docker Registry'),
                    ('ghcr',            'GitHub Container Registry (GHCR)'),
                    ('ecr',             'Amazon ECR'),
                    ('gcr',             'Google Container Registry (GCR)'),
                    ('acr-azure',       'Azure Container Registry (ACR)'),
                    ('tcr',             'Tencent Container Registry (TCR)'),
                    ('swr',             'Huawei SWR'),
                    ('harbor',          'Harbor'),
                    ('jfrog',           'JFrog Artifactory'),
                    ('generic',         'Generic (OCI / Docker v2)'),
                ],
                default='generic',
                max_length=32,
            ),
        ),
    ]
