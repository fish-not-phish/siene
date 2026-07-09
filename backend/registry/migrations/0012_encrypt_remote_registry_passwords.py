"""
Migration: encrypt all existing plaintext password_enc values on RemoteRegistry.

Uses the same registry.crypto helpers that the application uses at runtime.
Rows that are already encrypted (prefixed with "fernet1:") are skipped.
"""
from django.db import migrations


def encrypt_existing_passwords(apps, schema_editor):
    from registry.crypto import encrypt_field, _FERNET_PREFIX

    RemoteRegistry = apps.get_model('registry', 'RemoteRegistry')
    updated = 0
    for remote in RemoteRegistry.objects.all():
        if not remote.password_enc:
            continue
        # Already encrypted — skip
        if remote.password_enc.encode().startswith(_FERNET_PREFIX):
            continue
        remote.password_enc = encrypt_field(remote.password_enc)
        remote.save(update_fields=['password_enc'])
        updated += 1
    if updated:
        print(f'\n  Encrypted {updated} RemoteRegistry credential(s)')


def decrypt_existing_passwords(apps, schema_editor):
    """Reverse: decrypt back to plaintext (for rollback)."""
    from registry.crypto import decrypt_field

    RemoteRegistry = apps.get_model('registry', 'RemoteRegistry')
    for remote in RemoteRegistry.objects.all():
        if not remote.password_enc:
            continue
        remote.password_enc = decrypt_field(remote.password_enc)
        remote.save(update_fields=['password_enc'])


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0011_replication_job'),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_passwords, decrypt_existing_passwords),
    ]
