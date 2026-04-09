from typing import Literal

from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: int | None = None


class FolderResponse(BaseModel):
    id: int
    name: str
    parent_id: int | None
    is_system: bool = False


class FolderRename(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class FolderMove(BaseModel):
    parent_id: int | None = None


class FolderDelete(BaseModel):
    strategy: Literal["move_children_to_root", "delete_recursive"] = "move_children_to_root"


class EntryCreate(BaseModel):
    folder_id: int | None = None
    entry_type_code: str
    title: str
    login: str = ""
    password: str
    url: str = ""
    description: str = ""
    icon: str = ""
    level: str = "general"


class EntryResponse(BaseModel):
    id: int
    folder_id: int | None
    entry_type_code: str
    title: str
    login: str
    password: str
    url: str
    description: str
    icon: str = ""
    level: str = "general"
    created_by: str = ""


class EntryUpdate(BaseModel):
    folder_id: int | None = None
    entry_type_code: str = ""
    title: str = ""
    login: str = ""
    password: str = ""
    url: str = ""
    description: str = ""
    icon: str = ""
    level: str = ""


class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""


class RoleResponse(BaseModel):
    id: int
    name: str
    description: str


class PermissionUpsert(BaseModel):
    role_name: str
    entry_type_code: str
    can_read: bool
    can_write: bool


class RoleAssign(BaseModel):
    username: str
    role_name: str


class EntryTypeResponse(BaseModel):
    code: str
    title: str


class RoleUnassign(BaseModel):
    username: str
    role_name: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_superuser: bool
    source: str
    roles: list[str] = []
    access_levels: list[str] = []


class LdapConfigSave(BaseModel):
    enabled: bool = False
    server_url: str = ""
    use_ssl: bool = False
    bind_dn: str = ""
    bind_password: str | None = None      # None = keep existing stored password
    base_dn: str = ""
    user_filter: str = "(sAMAccountName={username})"
    username_attr: str = "sAMAccountName"
    email_attr: str = "mail"
    required_group_dn: str = ""
    auto_provision: bool = True
    default_role: str = ""


class LdapConfigResponse(BaseModel):
    enabled: bool
    server_url: str
    use_ssl: bool
    bind_dn: str
    bind_password_set: bool
    base_dn: str
    user_filter: str
    username_attr: str
    email_attr: str
    required_group_dn: str
    auto_provision: bool
    default_role: str
