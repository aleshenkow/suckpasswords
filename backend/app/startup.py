import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import engine
from .models import Entry, EntryType, Folder, LdapConfig, Role, SmtpConfig, User
from .security import (
    decrypt_secret,
    encrypt_secret,
    get_password_hash,
    is_legacy_ciphertext,
)


def run_migrations() -> None:
    """Apply Alembic migrations (the baseline revision is idempotent, so existing databases are adopted as-is)."""
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).with_name("migrations")))
    command.upgrade(cfg, "head")


def reencrypt_legacy_secrets(db: Session) -> None:
    """Upgrade secrets stored with the legacy key derivation to the current (v2) format."""
    upgraded = 0
    targets = (
        (Entry, "password"),
        (LdapConfig, "bind_password"),
        (SmtpConfig, "password"),
    )
    for model, attr in targets:
        for row in db.scalars(select(model)).all():
            value = getattr(row, attr) or ""
            if not is_legacy_ciphertext(value):
                continue
            try:
                setattr(row, attr, encrypt_secret(decrypt_secret(value)))
                upgraded += 1
            except Exception:  # noqa: BLE001
                logging.exception("Could not re-encrypt %s.%s id=%s; leaving as is", model.__name__, attr, row.id)
    if upgraded:
        db.commit()
        logging.info("Re-encrypted %d secret(s) to v2 format", upgraded)


def run_startup() -> None:
    if settings.app_secret_key in ("", "change_me"):
        raise RuntimeError(
            "APP_SECRET_KEY is empty or the default 'change_me'. Set a strong random secret in .env "
            "(e.g. `openssl rand -hex 32`) before starting the application."
        )
    if len(settings.app_secret_key) < 32:
        logging.warning("APP_SECRET_KEY is shorter than 32 characters; use a longer random secret.")

    run_migrations()

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
            db.add(Folder(name="General", parent_id=None, icon="📋", is_system=True))

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

        # Bootstrap SMTP config row (id=1) with defaults
        smtp_row = db.scalar(select(SmtpConfig).where(SmtpConfig.id == 1))
        if smtp_row is None:
            db.add(SmtpConfig(id=1))

        db.commit()

        reencrypt_legacy_secrets(db)
