# Load Celery app at Django startup so @shared_task decorators are registered
# and periodic tasks can be discovered by Beat.
from .celery import app as celery_app  # noqa: F401

__all__ = ('celery_app',)
