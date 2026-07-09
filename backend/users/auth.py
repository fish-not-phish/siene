import hashlib
from ninja.security import SessionAuth, HttpBearer


session_mfa_auth = SessionAuth()



class AdminSessionAuth(SessionAuth):
    """Session auth that additionally requires UserProfile.is_admin = True."""

    def authenticate(self, request, key):
        user = super().authenticate(request, key)
        if user is None:
            return None
        from users.models import UserProfile
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if not profile.is_admin:
            return None
        return user


admin_session_auth = AdminSessionAuth()


class RobotBearerAuth(HttpBearer):
    """
    Bearer token auth for robot accounts.

    Clients send:  Authorization: Bearer <plaintext_secret>

    The plaintext secret is SHA-256 hashed and matched against
    RobotAccount.secret_hash.  Expired or disabled robots are rejected.
    Returns the RobotAccount instance on success, None on failure.
    """

    def authenticate(self, request, token: str):
        from django.utils import timezone
        from registry.models import RobotAccount

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            robot = RobotAccount.objects.select_related('project').get(
                secret_hash=token_hash,
                disabled=False,
            )
        except RobotAccount.DoesNotExist:
            return None

        # Reject expired robots
        if robot.expires_at and robot.expires_at < timezone.now():
            return None

        return robot


robot_bearer_auth = RobotBearerAuth()
