import logging

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import settings
from .database import Base, engine
from .models import EntryType, Folder, LdapConfig, Role, SmtpConfig, User
from .security import encrypt_secret, get_password_hash


def run_startup() -> None:
    if settings.app_secret_key == "change_me":
        logging.warning(
            "SECURITY WARNING: APP_SECRET_KEY is the default 'change_me'. "
            "Set a strong random secret in your .env file before production use!"
        )

    Base.metadata.create_all(bind=engine)

    # Live migrations for new columns on existing tables
    with engine.connect() as conn:
        conn.execute(text("ALTER TABLE folders ADD COLUMN IF NOT EXISTS is_system BOOLEAN DEFAULT FALSE NOT NULL"))
        conn.execute(text("ALTER TABLE folders ADD COLUMN IF NOT EXISTS icon VARCHAR(32) DEFAULT '📁' NOT NULL"))
        conn.execute(text("ALTER TABLE entries ADD COLUMN IF NOT EXISTS level VARCHAR(32) DEFAULT 'general' NOT NULL"))
        conn.execute(text("ALTER TABLE entries ADD COLUMN IF NOT EXISTS created_by VARCHAR(128) DEFAULT '' NOT NULL"))
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0 NOT NULL")
        )
        conn.execute(
            text("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE DEFAULT NULL")
        )
        conn.execute(text("ALTER TABLE smtp_config ADD COLUMN IF NOT EXISTS anonymous BOOLEAN DEFAULT FALSE NOT NULL"))
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
