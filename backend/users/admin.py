from django.contrib import admin
from .models import UserProfile, SiteSettings


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ["user", "is_admin"]
    list_filter = ["is_admin"]
    search_fields = ["user__username", "user__email"]


@admin.register(SiteSettings)
class SiteSettingsAdmin(admin.ModelAdmin):
    list_display = ["allow_registration", "oidc_enabled", "oidc_provider_type"]