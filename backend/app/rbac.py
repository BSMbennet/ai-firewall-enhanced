"""Role hierarchy and delegation rules.

Roles are ordered. An actor may only manage members who rank strictly below them and may only
grant roles strictly below their own, so no role can create a peer or superior, edit the
Owner, or change itself. Authorization is always evaluated server-side from the stored role.
"""
from __future__ import annotations

from typing import Optional

ROLE_RANK = {"owner": 100, "admin": 80, "security": 60, "developer": 40, "member": 20, "viewer": 10}

# Roles an Owner/Admin may assign through invitations and role changes. "owner" is never assignable.
ASSIGNABLE_ROLES = frozenset({"admin", "security", "developer", "member", "viewer"})

# Roles that may read raw (per-request) audit rows. Aggregate dashboard statistics are open to all roles.
AUDIT_READER_ROLES = frozenset({"owner", "admin", "security", "viewer"})

# Roles that may use the AI gateway on their own behalf (read-only viewers may not).
AI_USER_ROLES = frozenset({"owner", "admin", "security", "developer", "member"})

BLOCKED_MEMBER_STATUSES = frozenset({"suspended", "removed"})


def rank(role: Optional[str]) -> int:
    return ROLE_RANK.get(str(role or "").strip().lower(), 0)


def assert_can_manage(actor_role: Optional[str], target_role: Optional[str], *, new_role: Optional[str] = None,
                      is_self: bool = False) -> None:
    """Raise PermissionError unless the actor may change the target member (and grant ``new_role``)."""
    if is_self:
        raise PermissionError("You cannot change your own role or status")
    if rank(actor_role) <= rank(target_role):
        raise PermissionError("You can only manage members with a lower role than your own")
    if new_role is not None and rank(new_role) >= rank(actor_role):
        raise PermissionError("You cannot grant a role equal to or higher than your own")


def assert_can_grant(actor_role: Optional[str], new_role: str) -> None:
    if rank(new_role) >= rank(actor_role):
        raise PermissionError("You cannot grant a role equal to or higher than your own")
