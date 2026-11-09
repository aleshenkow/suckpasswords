import logging

from fastapi import APIRouter, Depends, HTTPException, status
from ldap3 import Connection
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_admin
from ..models import LdapConfig, Role, User, UserRole
from ..schemas import (
    LdapConfigResponse,
    LdapConfigSave,
)
from ..security import decrypt_secret, encrypt_secret, get_password_hash
from ..services.audit import log_action
from ..services.ldap import build_ldap_server, get_ldap_row

router = APIRouter()


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


@router.get("/admin/ldap", response_model=LdapConfigResponse)
def get_ldap_config(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> LdapConfigResponse:
    cfg = get_ldap_row(db)
    if cfg is None:
        cfg = LdapConfig(id=1)
        db.add(cfg)
        db.commit()
    return _ldap_row_to_response(cfg)


@router.put("/admin/ldap", response_model=LdapConfigResponse)
def save_ldap_config(
    payload: LdapConfigSave,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> LdapConfigResponse:
    cfg = get_ldap_row(db)
    if cfg is None:
        cfg = LdapConfig(id=1)
        db.add(cfg)

    cfg.enabled = payload.enabled
    cfg.server_url = payload.server_url
    cfg.use_ssl = payload.use_ssl
    cfg.bind_dn = payload.bind_dn
    if payload.bind_password:  # empty string = don't change
        cfg.bind_password = encrypt_secret(payload.bind_password)
    cfg.base_dn = payload.base_dn
    cfg.user_filter = payload.user_filter
    cfg.username_attr = payload.username_attr
    cfg.email_attr = payload.email_attr
    cfg.required_group_dn = payload.required_group_dn
    cfg.auto_provision = payload.auto_provision
    cfg.default_role = payload.default_role
    log_action(
        db,
        user.username,
        "ldap.save",
        "ldap",
        "",
        f"enabled={cfg.enabled} server={cfg.server_url}",
    )
    db.commit()
    return _ldap_row_to_response(cfg)


@router.post("/admin/ldap/test")
def test_ldap_connection(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> dict[str, str]:
    cfg = get_ldap_row(db)
    if cfg is None or not cfg.server_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LDAP is not configured")
    try:
        server = build_ldap_server(cfg.server_url, cfg.use_ssl, connect_timeout=5)
        bind_pwd = decrypt_secret(cfg.bind_password) if cfg.bind_password else ""
        with Connection(server, cfg.bind_dn, bind_pwd, auto_bind=True) as conn:
            conn.search(search_base=cfg.base_dn, search_filter="(objectClass=*)", size_limit=1)
        return {"message": "Connection successful"}
    except Exception as exc:
        logging.exception("LDAP test connection failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


@router.post("/admin/ldap/sync")
def sync_ldap_users(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> dict[str, object]:
    cfg = get_ldap_row(db)
    if cfg is None or not cfg.enabled or not cfg.server_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LDAP is not enabled or configured")

    try:
        server = build_ldap_server(cfg.server_url, cfg.use_ssl, connect_timeout=5)
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
