"""
RBAC helpers for the registry app.

Role hierarchy (highest to lowest):
  system_admin > project_admin > maintainer > developer > guest
"""

from django.contrib.auth.models import User
from registry.models import Project, ProjectMember

ROLE_GUEST = ProjectMember.ROLE_GUEST
ROLE_DEVELOPER = ProjectMember.ROLE_DEVELOPER
ROLE_MAINTAINER = ProjectMember.ROLE_MAINTAINER
ROLE_ADMIN = ProjectMember.ROLE_ADMIN

_ROLE_RANK = {
    ROLE_GUEST: 1,
    ROLE_DEVELOPER: 2,
    ROLE_MAINTAINER: 3,
    ROLE_ADMIN: 4,
}


def get_member_role(user: User, project: Project) -> str | None:
    """Return the user's role in a project, or None if not a member."""
    try:
        m = ProjectMember.objects.get(project=project, user=user)
        return m.role
    except ProjectMember.DoesNotExist:
        return None


def has_role(user: User, project: Project, minimum_role: str) -> bool:
    """Return True if the user has at least `minimum_role` in the project."""
    # Django superusers (created via createsuperuser) may not have a UserProfile
    # row, so check is_superuser directly before falling back to UserProfile.is_admin.
    if getattr(user, 'is_superuser', False):
        return True
    from users.models import UserProfile
    try:
        if UserProfile.objects.get(user=user).is_admin:
            return True
    except UserProfile.DoesNotExist:
        pass

    role = get_member_role(user, project)
    if role is None:
        return False
    return _ROLE_RANK.get(role, 0) >= _ROLE_RANK.get(minimum_role, 99)


def can_pull(user: User | None, project: Project) -> bool:
    if project.public:
        return True
    if user is None or not user.is_authenticated:
        return False
    return has_role(user, project, ROLE_GUEST)


def can_push(user: User, project: Project) -> bool:
    return has_role(user, project, ROLE_DEVELOPER)


def can_delete(user: User, project: Project) -> bool:
    return has_role(user, project, ROLE_DEVELOPER)


def can_manage_members(user: User, project: Project) -> bool:
    return has_role(user, project, ROLE_ADMIN)


def can_manage_project(user: User, project: Project) -> bool:
    return has_role(user, project, ROLE_MAINTAINER)


def is_system_admin(user: User) -> bool:
    from users.models import UserProfile
    try:
        return UserProfile.objects.get(user=user).is_admin
    except UserProfile.DoesNotExist:
        return False
