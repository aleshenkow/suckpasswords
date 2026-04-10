from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(32), default="local")
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(nullable=True)

    roles: Mapped[list["UserRole"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")

    users: Mapped[list["UserRole"]] = relationship(back_populates="role", cascade="all, delete-orphan")
    permissions: Mapped[list["RoleEntryTypePermission"]] = relationship(
        back_populates="role", cascade="all, delete-orphan"
    )


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), index=True)

    user: Mapped[User] = relationship(back_populates="roles")
    role: Mapped[Role] = relationship(back_populates="users")


class EntryType(Base):
    __tablename__ = "entry_types"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(128))


class RoleEntryTypePermission(Base):
    __tablename__ = "role_entry_type_permissions"
    __table_args__ = (UniqueConstraint("role_id", "entry_type_id", name="uq_role_entry_type"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), index=True)
    entry_type_id: Mapped[int] = mapped_column(ForeignKey("entry_types.id", ondelete="CASCADE"), index=True)
    can_read: Mapped[bool] = mapped_column(Boolean, default=False)
    can_write: Mapped[bool] = mapped_column(Boolean, default=False)

    role: Mapped[Role] = relationship(back_populates="permissions")
    entry_type: Mapped[EntryType] = relationship()


class Folder(Base):
    __tablename__ = "folders"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("folders.id", ondelete="SET NULL"), nullable=True)
    icon: Mapped[str] = mapped_column(String(32), default="📁")
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)


class Entry(Base):
    __tablename__ = "entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    folder_id: Mapped[int | None] = mapped_column(ForeignKey("folders.id", ondelete="SET NULL"), nullable=True)
    entry_type_id: Mapped[int] = mapped_column(ForeignKey("entry_types.id", ondelete="RESTRICT"), index=True)

    title: Mapped[str] = mapped_column(String(255), index=True)
    login: Mapped[str] = mapped_column(String(255), default="")
    password: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(String(1024), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    icon: Mapped[str] = mapped_column(String(32), default="")
    level: Mapped[str] = mapped_column(String(32), default="general", index=True)
    created_by: Mapped[str] = mapped_column(String(128), default="")


class LdapConfig(Base):
    """Single-row table (id=1) that stores LDAP/AD connection settings."""
    __tablename__ = "ldap_config"

    id: Mapped[int] = mapped_column(primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    server_url: Mapped[str] = mapped_column(String(512), default="")
    use_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    bind_dn: Mapped[str] = mapped_column(String(512), default="")
    bind_password: Mapped[str] = mapped_column(Text, default="")          # AES-encrypted
    base_dn: Mapped[str] = mapped_column(String(512), default="")
    user_filter: Mapped[str] = mapped_column(String(512), default="(sAMAccountName={username})")
    username_attr: Mapped[str] = mapped_column(String(128), default="sAMAccountName")
    email_attr: Mapped[str] = mapped_column(String(128), default="mail")
    required_group_dn: Mapped[str] = mapped_column(String(512), default="")
    auto_provision: Mapped[bool] = mapped_column(Boolean, default=True)
    default_role: Mapped[str] = mapped_column(String(128), default="")
