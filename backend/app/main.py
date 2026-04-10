from pathlib import Path

import csv as csv_module
import io
import json
import os

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from ldap3 import ALL, Connection, Server
from sqlalchemy import select
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .database import Base, engine, get_db
from .models import Entry, EntryType, Folder, LdapConfig, Role, RoleEntryTypePermission, User, UserRole
from .schemas import (
    EntryCreate,
    EntryResponse,
    EntryTypeResponse,
    EntryUpdate,
    FolderCreate,
    FolderDelete,
    FolderMove,
    FolderRename,
    FolderResponse,
    LdapConfigResponse,
    LdapConfigSave,
    LoginRequest,
    PermissionUpsert,
    RoleAssign,
    RoleCreate,
    RoleResponse,
    RoleUnassign,
    TokenResponse,
    UserResponse,
)
from .security import (
    create_access_token,
    decrypt_secret,
    encrypt_secret,
    generate_password,
    get_password_hash,
    verify_password,
)

app = FastAPI(title="SuckPasswords")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ── Level-based access hierarchy ──────────────────────────────────
LEVEL_HIERARCHY: list[str] = ["general", "domain_admin", "enterprise_admin"]
ROLE_MAX_LEVEL: dict[str, int] = {
    "General": 0,
    "DomainAdmin": 1,
    "EnterpriseAdmin": 2,
}


def _user_access_levels(db: Session, user: User) -> list[str]:
    """Return ordered list of entry levels the user can read/write."""
    if user.is_superuser:
        return LEVEL_HIERARCHY[:]
    role_names = db.scalars(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user.id)
    ).all()
    max_idx = max((ROLE_MAX_LEVEL.get(rn, -1) for rn in role_names), default=-1)
    if max_idx < 0:
        return []
    return LEVEL_HIERARCHY[: max_idx + 1]


def _ui_file() -> Path:
    return Path(__file__).with_name("ui.html")


def _assert_admin(user: User) -> None:
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admin is allowed")


def _assert_valid_parent(db: Session, parent_id: int | None) -> None:
    if parent_id is None:
        return
    parent = db.scalar(select(Folder).where(Folder.id == parent_id))
    if parent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent folder not found")


def _folder_descendants_map(db: Session) -> dict[int, int | None]:
    rows = db.scalars(select(Folder)).all()
    return {row.id: row.parent_id for row in rows}


def _is_descendant(parent_map: dict[int, int | None], node_id: int, maybe_ancestor_id: int) -> bool:
    cursor = parent_map.get(node_id)
    while cursor is not None:
        if cursor == maybe_ancestor_id:
            return True
        cursor = parent_map.get(cursor)
    return False


def _collect_descendants(parent_map: dict[int, int | None], root_id: int) -> list[int]:
    children_by_parent: dict[int, list[int]] = {}
    for node_id, parent_id in parent_map.items():
        if parent_id is None:
            continue
        children_by_parent.setdefault(parent_id, []).append(node_id)

    descendants: list[int] = []
    stack: list[int] = [root_id]
    while stack:
        current = stack.pop()
        direct_children = children_by_parent.get(current, [])
        descendants.extend(direct_children)
        stack.extend(direct_children)
    return descendants


def _get_ldap_row(db: Session) -> LdapConfig | None:
    return db.scalar(select(LdapConfig).where(LdapConfig.id == 1))


def _do_ldap_auth(username: str, password: str, cfg: LdapConfig) -> bool:
    """Try to authenticate username/password against the configured LDAP/AD server."""
    if not cfg.server_url or not cfg.base_dn:
        return False
    try:
        server = Server(cfg.server_url, get_info=ALL, use_ssl=cfg.use_ssl)
        bind_pwd = decrypt_secret(cfg.bind_password) if cfg.bind_password else ""
        with Connection(server, cfg.bind_dn, bind_pwd, auto_bind=True) as svc:
            user_filter = cfg.user_filter.format(username=username)
            svc.search(
                search_base=cfg.base_dn,
                search_filter=user_filter,
                attributes=[cfg.username_attr, cfg.email_attr, "distinguishedName", "memberOf"],
            )
            if not svc.entries:
                return False
            entry = svc.entries[0]
            user_dn = str(entry.entry_dn)
            required_group = cfg.required_group_dn.strip()
            if required_group:
                groups = {str(g) for g in entry.memberOf.values} if hasattr(entry, "memberOf") else set()
                if required_group not in groups:
                    return False
        with Connection(server, user=user_dn, password=password, auto_bind=True):
            return True
    except Exception:
        return False


def _authenticate_with_ad(username: str, password: str) -> bool:
    from .config import settings

    if not settings.ad_enabled:
        return False
    if not settings.ad_server_uri or not settings.ad_base_dn:
        return False

    server = Server(settings.ad_server_uri, get_info=ALL)
    with Connection(server, settings.ad_bind_dn, settings.ad_bind_password, auto_bind=True) as service_conn:
        user_filter = settings.ad_user_filter.format(username=username)
        service_conn.search(
            search_base=settings.ad_base_dn,
            search_filter=user_filter,
            attributes=["distinguishedName", "memberOf"],
        )
        if not service_conn.entries:
            return False

        entry = service_conn.entries[0]
        user_dn = str(entry.entry_dn)
        required_group = settings.ad_required_group_dn.strip()
        if required_group:
            groups = {str(group) for group in entry.memberOf.values} if hasattr(entry, "memberOf") else set()
            if required_group not in groups:
                return False

    with Connection(server, user=user_dn, password=password, auto_bind=True):
        return True


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    from .security import decode_access_token

    username = decode_access_token(token)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.scalar(select(User).where(User.username == username, User.is_active.is_(True)))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@app.on_event("startup")
def on_startup() -> None:
    import logging
    from sqlalchemy import text

    from .config import settings

    if settings.app_secret_key == "change_me":
        logging.warning(
            "SECURITY WARNING: APP_SECRET_KEY is the default 'change_me'. "
            "Set a strong random secret in your .env file before production use!"
        )

    Base.metadata.create_all(bind=engine)

    # Live migrations for new columns on existing tables
    with engine.connect() as conn:
        conn.execute(text(
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS is_system BOOLEAN DEFAULT FALSE NOT NULL"
        ))
        conn.execute(text(
            "ALTER TABLE entries ADD COLUMN IF NOT EXISTS level VARCHAR(32) DEFAULT 'general' NOT NULL"
        ))
        conn.execute(text(
            "ALTER TABLE entries ADD COLUMN IF NOT EXISTS created_by VARCHAR(128) DEFAULT '' NOT NULL"
        ))
        conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0 NOT NULL"
        ))
        conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE DEFAULT NULL"
        ))
        conn.commit()

    with Session(engine) as db:
        for code, title in (("password", "Password"), ("ssh", "SSH"), ("api", "API token")):
            existing = db.scalar(select(EntryType).where(EntryType.code == code))
            if existing is None:
                db.add(EntryType(code=code, title=title))

        # Seed the 3 system roles and remove any extras
        system_role_names = {"General", "DomainAdmin", "EnterpriseAdmin"}
        for rname, rdesc in (
            ("General", "Basic access — General level only"),
            ("DomainAdmin", "Domain admin — General and DomainAdmin levels"),
            ("EnterpriseAdmin", "Full access — all levels"),
        ):
            if db.scalar(select(Role).where(Role.name == rname)) is None:
                db.add(Role(name=rname, description=rdesc))

        # Delete any legacy roles not in the system set
        for old_role in db.scalars(select(Role)).all():
            if old_role.name not in system_role_names:
                db.delete(old_role)

        # Check if any superuser already exists
        any_superuser = db.scalar(select(User).where(User.is_superuser.is_(True)))
        if any_superuser is None:
            # First run — admin credentials must be provided via APP_ADMIN_USERNAME / APP_ADMIN_PASSWORD
            if not settings.app_admin_username or not settings.app_admin_password:
                raise RuntimeError(
                    "No admin user exists yet. "
                    "Set APP_ADMIN_USERNAME and APP_ADMIN_PASSWORD in your .env file before starting the application."
                )
            admin = db.scalar(select(User).where(User.username == settings.app_admin_username))
            if admin is None:
                db.add(
                    User(
                        username=settings.app_admin_username,
                        email=settings.app_admin_email or f"{settings.app_admin_username}@local",
                        password_hash=get_password_hash(settings.app_admin_password),
                        is_superuser=True,
                        source="local",
                    )
                )

        # Ensure the "General" system folder exists
        general = db.scalar(select(Folder).where(Folder.is_system.is_(True)))
        if general is None:
            db.add(Folder(name="General", parent_id=None, is_system=True))

        # Bootstrap LDAP config row (id=1) from env vars if present
        ldap_row = db.scalar(select(LdapConfig).where(LdapConfig.id == 1))
        if ldap_row is None:
            ldap_row = LdapConfig(
                id=1,
                enabled=settings.ad_enabled,
                server_url=settings.ad_server_uri,
                bind_dn=settings.ad_bind_dn,
                bind_password=encrypt_secret(settings.ad_bind_password) if settings.ad_bind_password else "",
                base_dn=settings.ad_base_dn,
                user_filter=settings.ad_user_filter,
                required_group_dn=settings.ad_required_group_dn,
            )
            db.add(ldap_row)

        db.commit()


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    ui_path = _ui_file()
    if not ui_path.exists():
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="UI file missing")
    return HTMLResponse(content=ui_path.read_text(encoding="utf-8"))


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    from datetime import datetime, timedelta, timezone

    user = db.scalar(select(User).where(User.username == payload.username))
    ldap_cfg = _get_ldap_row(db)

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
        if not _do_ldap_auth(payload.username, payload.password, ldap_cfg):
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
        if not _authenticate_with_ad(payload.username, payload.password):
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
            db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Reset failure counter on successful login
    if user.failed_login_attempts or user.locked_until:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()

    token = create_access_token(payload.username)
    return TokenResponse(access_token=token)


@app.get("/users/me", response_model=UserResponse)
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
        access_levels=_user_access_levels(db, user),
    )


@app.post("/folders", response_model=FolderResponse)
def create_folder(payload: FolderCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> FolderResponse:
    _assert_admin(user)
    _assert_valid_parent(db, payload.parent_id)

    folder = Folder(name=payload.name.strip(), parent_id=payload.parent_id)
    db.add(folder)
    db.commit()
    db.refresh(folder)
    return FolderResponse(id=folder.id, name=folder.name, parent_id=folder.parent_id, is_system=folder.is_system)


@app.get("/folders", response_model=list[FolderResponse])
def list_folders(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[FolderResponse]:
    _ = user
    folders = db.scalars(select(Folder).order_by(Folder.parent_id, Folder.name)).all()
    # System folders (General) always first
    folders = sorted(folders, key=lambda f: (0 if f.is_system else 1, f.name))
    return [FolderResponse(id=f.id, name=f.name, parent_id=f.parent_id, is_system=f.is_system) for f in folders]


@app.put("/folders/{folder_id}/rename", response_model=FolderResponse)
def rename_folder(
    folder_id: int,
    payload: FolderRename,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> FolderResponse:
    _assert_admin(user)

    folder = db.scalar(select(Folder).where(Folder.id == folder_id))
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System folders cannot be renamed")

    folder.name = payload.name.strip()
    db.commit()
    db.refresh(folder)
    return FolderResponse(id=folder.id, name=folder.name, parent_id=folder.parent_id, is_system=folder.is_system)


@app.patch("/folders/{folder_id}/move", response_model=FolderResponse)
def move_folder(
    folder_id: int,
    payload: FolderMove,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> FolderResponse:
    _assert_admin(user)

    folder = db.scalar(select(Folder).where(Folder.id == folder_id))
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System folders cannot be moved")

    if payload.parent_id == folder_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Folder cannot be moved into itself")

    _assert_valid_parent(db, payload.parent_id)

    if payload.parent_id is not None:
        parent_map = _folder_descendants_map(db)
        parent_map[folder.id] = payload.parent_id
        if _is_descendant(parent_map, payload.parent_id, folder.id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Folder cannot be moved into its descendant",
            )

    folder.parent_id = payload.parent_id
    db.commit()
    db.refresh(folder)
    return FolderResponse(id=folder.id, name=folder.name, parent_id=folder.parent_id, is_system=folder.is_system)


@app.delete("/folders/{folder_id}")
def delete_folder(
    folder_id: int,
    payload: FolderDelete | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str | int]:
    _assert_admin(user)

    folder = db.scalar(select(Folder).where(Folder.id == folder_id))
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System folders cannot be deleted")

    strategy = payload.strategy if payload else "move_children_to_root"

    if strategy == "delete_recursive":
        parent_map = _folder_descendants_map(db)
        descendants = _collect_descendants(parent_map, folder.id)
        target_ids = [folder.id, *descendants]

        affected_entries = db.scalars(select(Entry).where(Entry.folder_id.in_(target_ids))).all()
        for entry in affected_entries:
            entry.folder_id = None

        folders_to_delete = db.scalars(select(Folder).where(Folder.id.in_(target_ids))).all()
        deleted_count = len(folders_to_delete)
        for target in folders_to_delete:
            db.delete(target)

        db.commit()
        return {
            "message": "Folder tree deleted",
            "deleted_folders": deleted_count,
            "reassigned_entries": len(affected_entries),
        }

    children = db.scalars(select(Folder).where(Folder.parent_id == folder.id)).all()
    for child in children:
        child.parent_id = None

    entries_in_folder = db.scalars(select(Entry).where(Entry.folder_id == folder.id)).all()
    for entry in entries_in_folder:
        entry.folder_id = None

    db.delete(folder)
    db.commit()
    return {
        "message": "Folder deleted and children moved to root",
        "moved_children": len(children),
        "reassigned_entries": len(entries_in_folder),
    }


@app.post("/entries", response_model=EntryResponse)
def create_entry(payload: EntryCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> EntryResponse:
    entry_type = db.scalar(select(EntryType).where(EntryType.code == payload.entry_type_code))
    if not entry_type:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry type not found")

    accessible_levels = _user_access_levels(db, user)
    entry_level = payload.level or "general"
    if entry_level not in accessible_levels:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry level")

    if payload.folder_id is not None:
        folder = db.scalar(select(Folder).where(Folder.id == payload.folder_id))
        if folder is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")

    entry = Entry(
        folder_id=payload.folder_id,
        entry_type_id=entry_type.id,
        title=payload.title,
        login=payload.login,
        password=encrypt_secret(payload.password),
        url=payload.url,
        description=payload.description,
        icon=payload.icon,
        level=entry_level,
        created_by=user.username,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    return EntryResponse(
        id=entry.id,
        folder_id=entry.folder_id,
        entry_type_code=entry_type.code,
        title=entry.title,
        login=entry.login,
        password=payload.password,
        url=entry.url,
        description=entry.description,
        icon=entry.icon,
        level=entry.level,
        created_by=entry.created_by,
    )


@app.get("/entries", response_model=list[EntryResponse])
def list_entries(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[EntryResponse]:
    accessible_levels = _user_access_levels(db, user)
    if not accessible_levels:
        return []
    entries = db.scalars(
        select(Entry).where(Entry.level.in_(accessible_levels)).order_by(Entry.title)
    ).all()
    response: list[EntryResponse] = []
    for entry in entries:
        entry_type = db.scalar(select(EntryType).where(EntryType.id == entry.entry_type_id))
        if entry_type is None:
            continue
        response.append(
            EntryResponse(
                id=entry.id,
                folder_id=entry.folder_id,
                entry_type_code=entry_type.code,
                title=entry.title,
                login=entry.login,
                password=decrypt_secret(entry.password),
                url=entry.url,
                description=entry.description,
                icon=entry.icon,
                level=entry.level,
                created_by=entry.created_by,
            )
        )
    return response


@app.put("/entries/{entry_id}", response_model=EntryResponse)
def update_entry(
    entry_id: int,
    payload: EntryUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EntryResponse:
    entry = db.scalar(select(Entry).where(Entry.id == entry_id))
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")

    entry_type = db.scalar(select(EntryType).where(EntryType.id == entry.entry_type_id))
    accessible_levels = _user_access_levels(db, user)
    if entry.level not in accessible_levels:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry")

    if payload.entry_type_code:
        new_type = db.scalar(select(EntryType).where(EntryType.code == payload.entry_type_code))
        if new_type is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry type not found")
        entry.entry_type_id = new_type.id
        entry_type = new_type

    if payload.folder_id is not None:
        folder = db.scalar(select(Folder).where(Folder.id == payload.folder_id))
        if folder is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    entry.folder_id = payload.folder_id

    if payload.title:
        entry.title = payload.title
    if payload.login is not None:
        entry.login = payload.login
    plain_pw = decrypt_secret(entry.password)
    if payload.password:
        entry.password = encrypt_secret(payload.password)
        plain_pw = payload.password
    if payload.url is not None:
        entry.url = payload.url
    if payload.description is not None:
        entry.description = payload.description
    if payload.icon is not None:
        entry.icon = payload.icon
    if payload.level:
        if payload.level not in accessible_levels:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry level")
        entry.level = payload.level

    db.commit()
    db.refresh(entry)
    return EntryResponse(
        id=entry.id,
        folder_id=entry.folder_id,
        entry_type_code=entry_type.code,
        title=entry.title,
        login=entry.login,
        password=plain_pw,
        url=entry.url,
        description=entry.description,
        icon=entry.icon,
        level=entry.level,
        created_by=entry.created_by,
    )


@app.delete("/entries/{entry_id}")
def delete_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    entry = db.scalar(select(Entry).where(Entry.id == entry_id))
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")
    accessible_levels = _user_access_levels(db, user)
    if entry.level not in accessible_levels:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry")
    db.delete(entry)
    db.commit()
    return {"message": "Deleted"}


@app.get("/password/generate")
def password_generate(length: int = 24, user: User = Depends(get_current_user)) -> dict[str, str]:
    _ = user
    return {"password": generate_password(length)}


@app.post("/admin/roles")
def create_role(payload: RoleCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict[str, str]:
    _assert_admin(user)
    existing = db.scalar(select(Role).where(Role.name == payload.name))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role already exists")

    db.add(Role(name=payload.name, description=payload.description))
    db.commit()
    return {"message": "Role created"}


@app.get("/admin/roles", response_model=list[RoleResponse])
def list_roles(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[RoleResponse]:
    _assert_admin(user)
    roles = db.scalars(select(Role).order_by(Role.name)).all()
    return [RoleResponse(id=r.id, name=r.name, description=r.description) for r in roles]


@app.get("/admin/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[UserResponse]:
    _assert_admin(user)
    users = db.scalars(select(User).order_by(User.username)).all()
    result = []
    for u in users:
        user_roles = db.scalars(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == u.id)
            .order_by(Role.name)
        ).all()
        result.append(UserResponse(
            id=u.id, username=u.username, email=u.email,
            is_active=u.is_active, is_superuser=u.is_superuser, source=u.source,
            roles=[r.name for r in user_roles],
        ))
    return result


@app.get("/admin/entry-types", response_model=list[EntryTypeResponse])
def list_entry_types(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[EntryTypeResponse]:
    _assert_admin(user)
    types = db.scalars(select(EntryType).order_by(EntryType.code)).all()
    return [EntryTypeResponse(code=t.code, title=t.title) for t in types]


@app.post("/admin/permissions")
def upsert_permission(
    payload: PermissionUpsert,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    _assert_admin(user)

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

    db.commit()
    return {"message": "Permission saved"}


@app.post("/admin/roles/assign")
def assign_role(payload: RoleAssign, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict[str, str]:
    _assert_admin(user)

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
    db.commit()
    return {"message": "Role assigned"}


@app.post("/admin/roles/unassign")
def unassign_role(payload: RoleUnassign, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict[str, str]:
    _assert_admin(user)

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
    db.commit()
    return {"message": "Role removed"}


@app.post("/admin/users/{user_id}/toggle-admin")
def toggle_admin(
    user_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _assert_admin(user)
    target = db.scalar(select(User).where(User.id == user_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot change your own admin status")
    target.is_superuser = not target.is_superuser
    db.commit()
    return {"is_superuser": target.is_superuser}


# ── LDAP / AD configuration ────────────────────────────────────────────────────

def _ldap_row_to_response(cfg: LdapConfig) -> LdapConfigResponse:
    return LdapConfigResponse(
        enabled=cfg.enabled,
        server_url=cfg.server_url,
        use_ssl=cfg.use_ssl,
        bind_dn=cfg.bind_dn,
        bind_password_set=bool(cfg.bind_password),
        base_dn=cfg.base_dn,
        user_filter=cfg.user_filter,
        username_attr=cfg.username_attr,
        email_attr=cfg.email_attr,
        required_group_dn=cfg.required_group_dn,
        auto_provision=cfg.auto_provision,
        default_role=cfg.default_role,
    )


@app.get("/admin/ldap", response_model=LdapConfigResponse)
def get_ldap_config(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> LdapConfigResponse:
    _assert_admin(user)
    cfg = _get_ldap_row(db)
    if cfg is None:
        cfg = LdapConfig(id=1)
        db.add(cfg)
        db.commit()
    return _ldap_row_to_response(cfg)


@app.put("/admin/ldap", response_model=LdapConfigResponse)
def save_ldap_config(
    payload: LdapConfigSave,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> LdapConfigResponse:
    _assert_admin(user)
    cfg = _get_ldap_row(db)
    if cfg is None:
        cfg = LdapConfig(id=1)
        db.add(cfg)

    cfg.enabled = payload.enabled
    cfg.server_url = payload.server_url
    cfg.use_ssl = payload.use_ssl
    cfg.bind_dn = payload.bind_dn
    if payload.bind_password:                                  # empty string = don't change
        cfg.bind_password = encrypt_secret(payload.bind_password)
    cfg.base_dn = payload.base_dn
    cfg.user_filter = payload.user_filter
    cfg.username_attr = payload.username_attr
    cfg.email_attr = payload.email_attr
    cfg.required_group_dn = payload.required_group_dn
    cfg.auto_provision = payload.auto_provision
    cfg.default_role = payload.default_role
    db.commit()
    return _ldap_row_to_response(cfg)


@app.post("/admin/ldap/test")
def test_ldap_connection(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    _assert_admin(user)
    cfg = _get_ldap_row(db)
    if cfg is None or not cfg.server_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LDAP is not configured")
    try:
        server = Server(cfg.server_url, get_info=ALL, use_ssl=cfg.use_ssl, connect_timeout=5)
        bind_pwd = decrypt_secret(cfg.bind_password) if cfg.bind_password else ""
        with Connection(server, cfg.bind_dn, bind_pwd, auto_bind=True) as conn:
            conn.search(search_base=cfg.base_dn, search_filter="(objectClass=*)", size_limit=1)
        return {"message": "Connection successful"}
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


@app.post("/admin/ldap/sync")
def sync_ldap_users(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, object]:
    _assert_admin(user)
    cfg = _get_ldap_row(db)
    if cfg is None or not cfg.enabled or not cfg.server_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LDAP is not enabled or configured")

    try:
        server = Server(cfg.server_url, get_info=ALL, use_ssl=cfg.use_ssl, connect_timeout=5)
        bind_pwd = decrypt_secret(cfg.bind_password) if cfg.bind_password else ""
        # Use wildcard for listing all matching users
        sync_filter = cfg.user_filter.format(username="*") if "{username}" in cfg.user_filter else cfg.user_filter
        attrs = [cfg.username_attr, cfg.email_attr, "memberOf"]
        with Connection(server, cfg.bind_dn, bind_pwd, auto_bind=True) as conn:
            conn.search(search_base=cfg.base_dn, search_filter=sync_filter, attributes=attrs)
            entries = conn.entries
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))

    required_group = cfg.required_group_dn.strip()
    default_role = db.scalar(select(Role).where(Role.name == cfg.default_role)) if cfg.default_role else None

    # Build set of usernames that are in the required group
    valid_usernames: set[str] = set()
    created = 0
    skipped_exists = 0
    skipped_no_attr = 0
    skipped_group = 0
    for entry in entries:
        attrs_dict: dict[str, list] = {k.lower(): v for k, v in entry.entry_attributes_as_dict.items()}

        # Check required group membership
        if required_group:
            member_of = [str(g) for g in attrs_dict.get("memberof", [])]
            if required_group not in member_of:
                skipped_group += 1
                continue

        uname_list = attrs_dict.get(cfg.username_attr.lower(), [])
        uname = str(uname_list[0]).strip() if uname_list else None
        if not uname:
            skipped_no_attr += 1
            continue

        valid_usernames.add(uname)
        existing = db.scalar(select(User).where(User.username == uname))
        if existing is not None:
            skipped_exists += 1
            continue
        email_list = attrs_dict.get(cfg.email_attr.lower(), [])
        email_raw = str(email_list[0]).strip() if email_list else ""
        email = email_raw if email_raw else f"{uname}@ldap.local"
        new_user = User(
            username=uname,
            email=email,
            password_hash=get_password_hash(uname),  # placeholder; login always via LDAP
            source="ldap",
            is_active=True,
            is_superuser=False,
        )
        db.add(new_user)
        db.flush()
        if default_role:
            db.add(UserRole(user_id=new_user.id, role_id=default_role.id))
        created += 1

    # Delete ldap users that are no longer in the required group (only when group filter is set)
    deleted = 0
    if required_group:
        ldap_users = db.scalars(select(User).where(User.source == "ldap", User.is_superuser.is_(False))).all()
        for lu in ldap_users:
            if lu.username not in valid_usernames:
                db.delete(lu)
                deleted += 1

    db.commit()
    return {
        "message": "Sync complete",
        "total_found": len(entries),
        "created": created,
        "deleted_not_in_group": deleted,
        "skipped_already_exists": skipped_exists,
        "skipped_no_username_attr": skipped_no_attr,
        "skipped_not_in_group": skipped_group,
    }


# ── Backup / Restore helpers ─────────────────────────────────────────────────

_BACKUP_MAGIC = b"SPBK"
_BACKUP_VERSION = b"\x01"
_PBKDF2_ITERATIONS = 260_000


def _backup_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return _BACKUP_MAGIC + _BACKUP_VERSION + salt + nonce + ct


def _backup_decrypt(data: bytes, password: str) -> bytes:
    if len(data) < 5 + 32 + 12 or data[:4] != _BACKUP_MAGIC or data[4:5] != _BACKUP_VERSION:
        raise ValueError("Invalid or corrupted backup file")
    salt, nonce, ct = data[5:37], data[37:49], data[49:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted backup")


def _entries_to_rows(db: Session) -> list[dict]:
    """Return all entries as plain-text dicts (passwords decrypted)."""
    folder_map = {f.id: f.name for f in db.scalars(select(Folder)).all()}
    type_map = {t.id: t.code for t in db.scalars(select(EntryType)).all()}
    rows = []
    for e in db.scalars(select(Entry)).all():
        rows.append({
            "title": e.title,
            "login": e.login,
            "password": decrypt_secret(e.password),
            "url": e.url,
            "description": e.description,
            "icon": e.icon,
            "level": e.level,
            "entry_type_code": type_map.get(e.entry_type_id, "password"),
            "folder_name": folder_map.get(e.folder_id, "") if e.folder_id else "",
        })
    return rows


def _import_rows(db: Session, rows: list[dict]) -> tuple[int, int]:
    """Create entries from a list of dicts. Returns (imported, skipped)."""
    folder_cache: dict[str, int] = {}
    type_cache: dict[str, int] = {}

    def get_folder_id(name: str) -> int | None:
        if not name:
            # default to General system folder
            general = db.scalar(select(Folder).where(Folder.is_system.is_(True)))
            return general.id if general else None
        if name in folder_cache:
            return folder_cache[name]
        f = db.scalar(select(Folder).where(Folder.name == name))
        if f is None:
            f = Folder(name=name)
            db.add(f)
            db.flush()
        folder_cache[name] = f.id
        return f.id

    def get_type_id(code: str) -> int | None:
        code = code or "password"
        if code in type_cache:
            return type_cache[code]
        t = db.scalar(select(EntryType).where(EntryType.code == code))
        if t is None:
            return None
        type_cache[code] = t.id
        return t.id

    imported = skipped = 0
    for row in rows:
        title = (row.get("title") or "").strip()
        password = (row.get("password") or "").strip()
        if not title or not password:
            skipped += 1
            continue
        type_id = get_type_id(row.get("entry_type_code", "password"))
        if type_id is None:
            skipped += 1
            continue
        folder_id = get_folder_id(row.get("folder_name", ""))
        db.add(Entry(
            folder_id=folder_id,
            entry_type_id=type_id,
            title=title,
            login=row.get("login", ""),
            password=encrypt_secret(password),
            url=row.get("url", ""),
            description=row.get("description", ""),
            icon=row.get("icon", ""),
            level=row.get("level", "general"),
        ))
        imported += 1
    return imported, skipped


# ── Backup endpoint ──────────────────────────────────────────────────────────

@app.post("/admin/backup")
def create_backup(
    password: str = Form(..., min_length=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    _assert_admin(user)
    rows = _entries_to_rows(db)
    payload = json.dumps({
        "version": 1,
        "exported_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "entries": rows,
    }, ensure_ascii=False).encode("utf-8")
    encrypted = _backup_encrypt(payload, password)
    return StreamingResponse(
        io.BytesIO(encrypted),
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=suckpasswords.spbackup"},
    )


@app.post("/admin/restore")
async def restore_backup(
    password: str = Form(..., min_length=1),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _assert_admin(user)
    raw = await file.read()
    try:
        plaintext = _backup_decrypt(raw, password)
        data = json.loads(plaintext.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    rows = data.get("entries", [])
    # Full restore: delete all existing entries, then re-import
    for e in db.scalars(select(Entry)).all():
        db.delete(e)
    db.flush()
    imported, skipped = _import_rows(db, rows)
    db.commit()
    return {"message": "Restore complete", "imported": imported, "skipped": skipped}


# ── Export CSV ──────────────────────────────────────────────────────────────

@app.get("/admin/export/csv")
def export_csv(
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    _assert_admin(user)
    buf = io.StringIO()
    fields = ["title", "login", "password", "url", "description", "icon", "level", "entry_type_code", "folder_name"]
    writer = csv_module.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    # Example row so the user understands the format
    writer.writerow({
        "title": "Example — My GitHub",
        "login": "username",
        "password": "YourPasswordHere",
        "url": "https://github.com",
        "description": "Optional notes",
        "icon": "🐙",
        "level": "general",
        "entry_type_code": "password",
        "folder_name": "General",
    })
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=suckpasswords_import_template.csv"},
    )


# ── Import CSV ──────────────────────────────────────────────────────────────

@app.post("/admin/import/csv")
async def import_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _assert_admin(user)
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")  # handle BOM from Excel
        reader = csv_module.DictReader(io.StringIO(text))
        rows = list(reader)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid CSV: {exc}")
    imported, skipped = _import_rows(db, rows)
    db.commit()
    return {"message": "Import complete", "imported": imported, "skipped": skipped}

