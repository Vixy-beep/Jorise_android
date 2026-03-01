from django.apps import AppConfig


class EdrConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'edr'
    verbose_name = 'Endpoint Detection and Response'
