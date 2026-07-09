from django.apps import AppConfig


class RegistryConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'registry'

    def ready(self):
        pass  # Audit logging is handled explicitly in api.py via log_action()
