from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0012_encrypt_remote_registry_passwords'),
    ]

    operations = [
        migrations.AlterField(
            model_name='remoteregistry',
            name='password_enc',
            field=models.TextField(
                blank=True,
                help_text='Encrypted credential (Fernet). Never expose in API responses.',
            ),
        ),
    ]
