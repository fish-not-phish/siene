from django.contrib import admin
from registry.models import (
    Project, ProjectMember, Repository, Tag,
    RobotAccount, AuditLog, VulnerabilityScan,
)


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'owner', 'public', 'created_at')
    search_fields = ('name', 'display_name')
    list_filter = ('public',)


@admin.register(ProjectMember)
class ProjectMemberAdmin(admin.ModelAdmin):
    list_display = ('project', 'user', 'role')
    list_filter = ('role',)


@admin.register(Repository)
class RepositoryAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'pull_count', 'push_count', 'updated_at')
    search_fields = ('name', 'project__name')


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'digest', 'size_bytes', 'pushed_at')
    search_fields = ('name', 'repository__name')


@admin.register(RobotAccount)
class RobotAccountAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'project', 'disabled', 'expires_at', 'created_at')
    list_filter = ('disabled',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'username', 'operation', 'resource_type', 'resource', 'result')
    list_filter = ('operation', 'result')
    readonly_fields = ('timestamp',)


@admin.register(VulnerabilityScan)
class VulnerabilityScanAdmin(admin.ModelAdmin):
    list_display = ('tag', 'scanner', 'status', 'started_at', 'finished_at')
    list_filter = ('status', 'scanner')
