from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import get_current_user
from ..models import Role, User, UserRole
from ..schemas import (
    LoginRequest,
    TokenResponse,
    UserResponse,
)
from ..security import (
    burn_password_check,
    create_access_token,
    get_password_hash,
    verify_password,
)
from ..services.access import user_access_levels
from ..services.audit import log_action
from ..services.ldap import authenticate_with_ad, do_ldap_auth, get_ldap_row

router = APIRouter()


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.scalar(select(User).where(User.username == payload.username))
    ldap_cfg = get_ldap_row(db)
    if user is None:
        burn_password_check(payload.password)  # keep timing similar for unknown users

    # ── Lockout check ───────────────────────────────────────────────
    if user and user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account locked — too many failed attempts. Try again in 15 minutes.",
        )

    auth_ok = True

    if user and user.source == "local":
        if not verify_password(payload.password, user.password_hash):
            auth_ok = False
    elif ldap_cfg and ldap_cfg.enabled:
        if not do_ldap_auth(payload.username, payload.password, ldap_cfg):
            auth_ok = False
        elif user is None:
            if not ldap_cfg.auto_provision:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Auto-provisioning is disabled")
            user = User(
                username=payload.username,
                email=f"{payload.username}@ldap.local",
                password_hash=get_password_hash(payload.password),
                source="ldap",
                is_active=True,
                is_superuser=False,
            )
            db.add(user)
            db.flush()
            if ldap_cfg.default_role:
                role = db.scalar(select(Role).where(Role.name == ldap_cfg.default_role))
                if role:
                    db.add(UserRole(user_id=user.id, role_id=role.id))
            db.commit()
    else:
        # Fallback: legacy env-var based AD auth
        if not authenticate_with_ad(payload.username, payload.password):
            auth_ok = False
        elif user is None:
            user = User(
                username=payload.username,
                email=f"{payload.username}@ad.local",
                password_hash=get_password_hash(payload.password),
                source="ad",
                is_active=True,
                is_superuser=False,
            )
            db.add(user)
            db.commit()

    if not auth_ok:
        # Track failure and lock after 5 consecutive bad attempts
        if user is not None:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        log_action(db, payload.username[:128], "auth.failed", "user", "", "invalid credentials")
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Reset failure counter on successful login
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    log_action(db, user.username, "auth.login", "user", user.id, f"remember_me={payload.remember_me}")
    db.commit()

    if payload.remember_me:
        token = create_access_token(payload.username, settings.app_remember_me_expire_minutes)
    else:
        token = create_access_token(payload.username)
    return TokenResponse(access_token=token)


@router.get("/users/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> UserResponse:
    user_roles = db.scalars(
        select(Role.name).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user.id)
    ).all()
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        source=user.source,
        roles=list(user_roles),
        access_levels=user_access_levels(db, user),
    )
