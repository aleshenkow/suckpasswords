from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Role, User, UserRole

# ── Level-based access hierarchy ──────────────────────────────────
LEVEL_HIERARCHY: list[str] = ["general", "domain_admin", "enterprise_admin"]
ROLE_MAX_LEVEL: dict[str, int] = {
    "General": 0,
    "DomainAdmin": 1,
    "EnterpriseAdmin": 2,
}


def user_access_levels(db: Session, user: User) -> list[str]:
    """Return ordered list of entry levels the user can read/write."""
    if user.is_superuser:
        return LEVEL_HIERARCHY[:]
    role_names = db.scalars(
        select(Role.name).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user.id)
    ).all()
    max_idx = max((ROLE_MAX_LEVEL.get(rn, -1) for rn in role_names), default=-1)
    if max_idx < 0:
        return []
    return LEVEL_HIERARCHY[: max_idx + 1]
