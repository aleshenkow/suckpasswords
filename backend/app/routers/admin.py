from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_admin
from ..models import AuditLog, EntryType, Role, RoleEntryTypePermission, User, UserRole
from ..schemas import (
    AuditLogResponse,
    EntryTypeResponse,
    PermissionUpsert,
    RoleAssign,
    RoleCreate,
    RoleResponse,
    RoleUnassign,
    UserResponse,
)
from ..services.audit import log_action

router = APIRouter()


@router.post("/admin/roles")
def create_role(
    payload: RoleCreate, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> dict[str, str]:
    existing = db.scalar(select(Role).where(Role.name == payload.name))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role already exists")

    db.add(Role(name=payload.name, description=payload.description))
    log_action(db, user.username, "role.create", "role", payload.name, f"description={payload.description!r}")
    db.commit()
    return {"message": "Role created"}


@router.get("/admin/roles", response_model=list[RoleResponse])
def list_roles(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> list[RoleResponse]:
    roles = db.scalars(select(Role).order_by(Role.name)).all()
    return [RoleResponse(id=r.id, name=r.name, description=r.description) for r in roles]


@router.get("/admin/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> list[UserResponse]:
    users = db.scalars(select(User).order_by(User.username)).all()
    roles_by_user: dict[int, list[str]] = {}
    for user_id, role_name in db.execute(
        select(UserRole.user_id, Role.name).join(Role, UserRole.role_id == Role.id).order_by(Role.name)
    ):
        roles_by_user.setdefault(user_id, []).append(role_name)
    return [
        UserResponse(
            id=u.id,
            username=u.username,
            email=u.email,
            is_active=u.is_active,
            is_superuser=u.is_superuser,
            source=u.source,
            roles=roles_by_user.get(u.id, []),
        )
        for u in users
    ]


@router.get("/admin/entry-types", response_model=list[EntryTypeResponse])
def list_entry_types(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> list[EntryTypeResponse]:
    types = db.scalars(select(EntryType).order_by(EntryType.code)).all()
    return [EntryTypeResponse(code=t.code, title=t.title) for t in types]


@router.post("/admin/permissions")
def upsert_permission(
    payload: PermissionUpsert,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> dict[str, str]:
    role = db.scalar(select(Role).where(Role.name == payload.role_name))
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    entry_type = db.scalar(select(EntryType).where(EntryType.code == payload.entry_type_code))
    if entry_type is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry type not found")

    permission = db.scalar(
        select(RoleEntryTypePermission).where(
            RoleEntryTypePermission.role_id == role.id,
            RoleEntryTypePermission.entry_type_id == entry_type.id,
        )
    )

    if permission is None:
        permission = RoleEntryTypePermission(
            role_id=role.id,
            entry_type_id=entry_type.id,
            can_read=payload.can_read,
            can_write=payload.can_write,
        )
        db.add(permission)
    else:
        permission.can_read = payload.can_read
        permission.can_write = payload.can_write

    log_action(
        db,
        user.username,
        "permission.upsert",
        "role",
        payload.role_name,
        f"entry_type={payload.entry_type_code} read={payload.can_read} write={payload.can_write}",
    )
    db.commit()
    return {"message": "Permission saved"}


@router.post("/admin/roles/assign")
def assign_role(
    payload: RoleAssign, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> dict[str, str]:
    target_user = db.scalar(select(User).where(User.username == payload.username))
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    role = db.scalar(select(Role).where(Role.name == payload.role_name))
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    existing = db.scalar(select(UserRole).where(UserRole.user_id == target_user.id, UserRole.role_id == role.id))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role already assigned to this user")
    db.add(UserRole(user_id=target_user.id, role_id=role.id))
    log_action(
        db,
        user.username,
        "role.assign",
        "user",
        target_user.id,
        f"username={target_user.username} role={payload.role_name}",
    )
    db.commit()
    return {"message": "Role assigned"}


@router.post("/admin/roles/unassign")
def unassign_role(
    payload: RoleUnassign, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> dict[str, str]:
    target_user = db.scalar(select(User).where(User.username == payload.username))
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    role = db.scalar(select(Role).where(Role.name == payload.role_name))
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    existing = db.scalar(select(UserRole).where(UserRole.user_id == target_user.id, UserRole.role_id == role.id))
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not assigned to this user")
    db.delete(existing)
    log_action(
        db,
        user.username,
        "role.unassign",
        "user",
        target_user.id,
        f"username={target_user.username} role={payload.role_name}",
    )
    db.commit()
    return {"message": "Role removed"}


@router.post("/admin/users/{user_id}/toggle-admin")
def toggle_admin(
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> dict[str, object]:
    target = db.scalar(select(User).where(User.id == user_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot change your own admin status")
    target.is_superuser = not target.is_superuser
    log_action(
        db,
        user.username,
        "user.toggle_admin",
        "user",
        target.id,
        f"username={target.username} is_superuser={target.is_superuser}",
    )
    db.commit()
    return {"is_superuser": target.is_superuser}


# ── Audit log ─────────────────────────────────────────────────────────────────


@router.get("/admin/logs", response_model=list[AuditLogResponse])
def list_audit_logs(
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> list[AuditLogResponse]:
    limit = max(1, min(int(limit or 200), 1000))
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit)).all()
    return [
        AuditLogResponse(
            id=r.id,
            created_at=r.created_at.isoformat() if r.created_at else "",
            username=r.username,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            details=r.details,
        )
        for r in rows
    ]
