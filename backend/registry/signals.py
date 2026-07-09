"""
Auto-create audit log entries on model changes.
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from registry.models import Project, AuditLog


@receiver(post_save, sender=Project)
def log_project_save(sender, instance, created, **kwargs):
    op = AuditLog.OP_CREATE if created else AuditLog.OP_UPDATE
    AuditLog.objects.create(
        project=instance,
        resource_type=AuditLog.RESOURCE_PROJECT,
        resource=instance.name,
        operation=op,
        result=True,
    )


@receiver(post_delete, sender=Project)
def log_project_delete(sender, instance, **kwargs):
    AuditLog.objects.create(
        resource_type=AuditLog.RESOURCE_PROJECT,
        resource=instance.name,
        operation=AuditLog.OP_DELETE,
        result=True,
    )
