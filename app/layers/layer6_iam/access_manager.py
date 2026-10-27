
from datetime import datetime, timezone

from app.layers.layer6_iam.schemas import (
    AccessRequest,
    MFAChallenge,
    MFAStatus,
    Permission,
    Role,
    RolePermission,
    UserIdentity,
)


class IAMAccessManager:
    """
    In-memory IAM and RBAC policy manager.

    This is an independent policy foundation, not a production
    identity provider or a complete MFA implementation.
    """

    def __init__(
        self,
        users: list[UserIdentity] | None = None,
        role_permissions: list[RolePermission] | None = None,
    ) -> None:
        self._users: dict[str, UserIdentity] = {}
        self._role_permissions: dict[Role, set[Permission]] = {}
        self._mfa_challenges: dict[str, MFAChallenge] = {}

        for mapping in role_permissions or []:
            self.set_role_permissions(mapping)

        for user in users or []:
            self.add_user(user)

    def add_user(self, user: UserIdentity) -> None:
        """Add a user, rejecting duplicate user IDs."""
        if user.user_id in self._users:
            raise ValueError(f"Duplicate user ID: {user.user_id}")

        if any(
            existing.username.casefold() == user.username.casefold()
            for existing in self._users.values()
        ):
            raise ValueError(f"Duplicate username: {user.username}")

        if any(
            existing.email.casefold() == user.email.casefold()
            for existing in self._users.values()
        ):
            raise ValueError(f"Duplicate email: {user.email}")

        self._users[user.user_id] = user

    def get_user(self, user_id: str) -> UserIdentity | None:
        """Return a user by ID."""
        return self._users.get(user_id)

    def list_users(self) -> list[UserIdentity]:
        """Return all registered users."""
        return list(self._users.values())

    def set_role_permissions(
        self,
        mapping: RolePermission,
    ) -> None:
        """Replace the permission set assigned to a role."""
        self._role_permissions[mapping.role] = set(
            mapping.permissions
        )

    def get_role_permissions(self, role: Role) -> set[Permission]:
        """Return a copy of a role's permissions."""
        return set(self._role_permissions.get(role, set()))

    def authorize(self, request: AccessRequest) -> bool:
        """
        Check whether a registered, active user has the requested
        permission and has verified MFA.

        In a real application, MFA status must come from a trusted,
        server-side authentication session.
        """
        user = self._users.get(request.user_id)

        if user is None or not user.active:
            return False

        if user.mfa_status != MFAStatus.VERIFIED:
            return False

        for role in user.roles:
            permissions = self._role_permissions.get(role, set())

            if request.permission in permissions:
                return True

        return False

    def register_mfa_challenge(
        self,
        challenge: MFAChallenge,
    ) -> None:
        """Register challenge metadata with a unique challenge ID."""
        if challenge.challenge_id in self._mfa_challenges:
            raise ValueError(
                f"Duplicate challenge ID: {challenge.challenge_id}"
            )

        if challenge.user_id not in self._users:
            raise ValueError("Cannot register challenge for unknown user")

        if challenge.verified:
            raise ValueError(
                "New MFA challenges cannot start as verified"
            )

        self._mfa_challenges[challenge.challenge_id] = challenge

    def get_mfa_challenge(
        self,
        challenge_id: str,
    ) -> MFAChallenge | None:
        """Return challenge metadata if registered."""
        return self._mfa_challenges.get(challenge_id)

    def consume_mfa_attempt(
        self,
        challenge_id: str,
    ) -> bool:
        """
        Consume one attempt on a pending, unexpired challenge.

        Returns False for missing, expired, verified, or exhausted
        challenges. This does not verify an OTP.
        """
        challenge = self._mfa_challenges.get(challenge_id)

        if challenge is None:
            return False

        if challenge.verified or challenge.attempts_remaining <= 0:
            return False

        now = datetime.now(timezone.utc)

        if challenge.expires_at <= now:
            return False

        challenge.attempts_remaining -= 1
        return True

    def mark_mfa_verified(self, challenge_id: str) -> bool:
        """
        Mark a challenge verified only if it is pending and unexpired.

        IMPORTANT: Call this only after an independent, trusted
        OTP/authenticator verification succeeds. This method alone
        does not prove possession of an MFA factor.
        """
        challenge = self._mfa_challenges.get(challenge_id)

        if challenge is None:
            return False

        if challenge.verified or challenge.attempts_remaining <= 0:
            return False

        if challenge.expires_at <= datetime.now(timezone.utc):
            return False

        user = self._users.get(challenge.user_id)

        if user is None or not user.active:
            return False

        challenge.verified = True
        self._users[user.user_id] = user.model_copy(
            update={"mfa_status": MFAStatus.VERIFIED}
        )

        return True
