"""
Celery application for Siene.

Queues
------
default   general background work (GC, registry sync, replication)
scans     vulnerability scanning (Trivy) — can be scaled independently
sbom      SBOM generation (Syft) — slow, isolated to avoid starving scans
"""

import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

app = Celery('siene')

# Read CELERY_* keys from Django settings (prefixed so they don't clash)
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in all INSTALLED_APPS
app.autodiscover_tasks()
