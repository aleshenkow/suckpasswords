from urllib.parse import urlparse

from ldap3 import NONE, Connection, Server
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import LdapConfig
from ..security import decrypt_secret


def get_ldap_row(db: Session) -> LdapConfig | None:
    return db.scalar(select(LdapConfig).where(LdapConfig.id == 1))


def build_ldap_server(server_url: str, use_ssl: bool, connect_timeout: int | None = None) -> Server:
    """Build ldap3 Server from either host:port or ldap(s)://host:port input."""
    raw_value = server_url.strip()
    parsed = urlparse(raw_value)

    host = raw_value
    port = None
    effective_use_ssl = use_ssl

    if parsed.scheme in {"ldap", "ldaps"}:
        if not parsed.hostname:
            raise ValueError("LDAP server URL must include a valid hostname")
        host = parsed.hostname
        port = parsed.port
        effective_use_ssl = parsed.scheme == "ldaps"

    # NONE avoids schema/rootDSE discovery on each login and cuts LDAP auth latency.
    return Server(host, port=port, get_info=NONE, use_ssl=effective_use_ssl, connect_timeout=connect_timeout)


def do_ldap_auth(username: str, password: str, cfg: LdapConfig) -> bool:
    """Try to authenticate username/password against the configured LDAP/AD server."""
    if not cfg.server_url or not cfg.base_dn:
        return False
    try:
        server = build_ldap_server(cfg.server_url, cfg.use_ssl)
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


def authenticate_with_ad(username: str, password: str) -> bool:
    if not settings.ad_enabled:
        return False
    if not settings.ad_server_uri or not settings.ad_base_dn:
        return False

    server = build_ldap_server(settings.ad_server_uri, settings.ad_server_uri.startswith("ldaps://"))
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
