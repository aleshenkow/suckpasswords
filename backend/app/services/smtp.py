import logging
import smtplib
import threading
import time
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Entry, SmtpConfig, User
from ..security import decrypt_secret
from .access import LEVEL_HIERARCHY, user_access_levels


def get_smtp_row(db: Session) -> "SmtpConfig | None":
    return db.scalar(select(SmtpConfig).where(SmtpConfig.id == 1))


def smtp_send(cfg_data: dict, recipients: list[str], subject: str, body: str) -> None:
    """Send a single email synchronously. Raises on error."""

    if not cfg_data.get("host") or not recipients:
        return
    msg = EmailMessage()
    from_email = cfg_data.get("from_email") or cfg_data.get("username") or "noreply@suckpasswords.local"
    from_name = cfg_data.get("from_name") or "SuckPasswords"
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)

    host = cfg_data["host"]
    port = int(cfg_data.get("port") or (465 if cfg_data.get("use_ssl") else 587))
    anonymous = bool(cfg_data.get("anonymous"))
    username = cfg_data.get("username") or ""
    password = cfg_data.get("password_plain") or ""

    if cfg_data.get("use_ssl"):
        with smtplib.SMTP_SSL(host, port, timeout=15) as s:
            if not anonymous and username:
                s.login(username, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=15) as s:
            if cfg_data.get("use_tls"):
                s.starttls()
            if not anonymous and username:
                s.login(username, password)
            s.send_message(msg)


def smtp_cfg_to_data(cfg: SmtpConfig) -> dict:
    return {
        "host": cfg.host,
        "port": cfg.port,
        "use_tls": cfg.use_tls,
        "use_ssl": cfg.use_ssl,
        "anonymous": cfg.anonymous,
        "username": cfg.username,
        "password_plain": decrypt_secret(cfg.password) if cfg.password else "",
        "from_email": cfg.from_email,
        "from_name": cfg.from_name,
    }


def gather_notification_recipients(db: Session, entry_level: str, exclude_username: str) -> list[str]:
    """Return emails of active users whose max access level >= entry_level."""
    if entry_level not in LEVEL_HIERARCHY:
        target_idx = 0
    else:
        target_idx = LEVEL_HIERARCHY.index(entry_level)

    users = db.scalars(select(User).where(User.is_active.is_(True))).all()
    logging.info("SMTP recipients: checking %d active user(s) for level=%s", len(users), entry_level)
    emails: list[str] = []
    for u in users:
        if u.username == exclude_username:
            logging.info("  skip %s — is actor (excluded)", u.username)
            continue
        if not u.email or "@" not in u.email:
            logging.info("  skip %s — no valid email (email=%r)", u.username, u.email)
            continue
        # Skip placeholder local emails that won't deliver
        domain = u.email.rsplit("@", 1)[-1].lower()
        if domain in {"local", "ldap.local", "ad.local"}:
            logging.info("  skip %s — placeholder domain (%s)", u.username, domain)
            continue
        levels = user_access_levels(db, u)
        if not levels:
            logging.info("  skip %s — no roles assigned", u.username)
            continue
        max_idx = LEVEL_HIERARCHY.index(levels[-1])
        if max_idx >= target_idx:
            logging.info("  include %s <%s> (max_level=%s)", u.username, u.email, levels[-1])
            emails.append(u.email)
        else:
            logging.info("  skip %s — insufficient level (max=%s, required=%s)", u.username, levels[-1], entry_level)
    logging.info("SMTP recipients result: %s", emails or "(none)")
    return emails


def notify_async(cfg_data: dict, recipients: list[str], subject: str, body: str) -> None:
    """Fire-and-forget email delivery in a background thread."""
    if not cfg_data or not recipients:
        return

    def _runner() -> None:
        for attempt in range(1, 4):
            try:
                logging.info(
                    "SMTP sending '%s' to %s via %s:%s", subject, recipients, cfg_data.get("host"), cfg_data.get("port")
                )
                smtp_send(cfg_data, recipients, subject, body)
                logging.info("SMTP send OK -> %s", recipients)
                return
            except Exception as exc:  # noqa: BLE001
                logging.warning("SMTP notification failed (attempt %d/3): %s", attempt, exc)
                if attempt < 3:
                    time.sleep(5 * attempt)

    threading.Thread(target=_runner, daemon=True).start()


def notify_entry_event(db: Session, entry: Entry, entry_type_code: str, actor_username: str, event: str) -> None:
    """Email notification for entry create/update/delete, respecting role grid."""
    cfg = get_smtp_row(db)
    if cfg is None or not cfg.enabled or not cfg.host:
        logging.info("SMTP notify skip [%s]: SMTP not configured or disabled", event)
        return
    flag = {
        "created": cfg.notify_on_create,
        "updated": cfg.notify_on_update,
        "deleted": cfg.notify_on_delete,
    }.get(event, False)
    if not flag:
        logging.info("SMTP notify skip [%s]: notify_%s flag is off", event, event)
        return
    recipients = gather_notification_recipients(db, entry.level, actor_username)
    if not recipients:
        logging.warning(
            "SMTP notify skip [%s]: no recipients for entry '%s' (level=%s, actor=%s). "
            "Check that other users have valid emails and appropriate roles.",
            event,
            entry.title,
            entry.level,
            actor_username,
        )
        return
    logging.info("SMTP notify [%s]: sending to %s", event, recipients)
    level_label = {
        "general": "General",
        "domain_admin": "Domain Admin",
        "enterprise_admin": "Enterprise Admin",
    }.get(entry.level, entry.level)
    subject = f"[SuckPasswords] Entry {event}: {entry.title} ({level_label})"
    body = (
        f"An entry was {event} in SuckPasswords.\n\n"
        f"Title       : {entry.title}\n"
        f"Type        : {entry_type_code}\n"
        f"Access level: {level_label}\n"
        f"Performed by: {actor_username}\n"
        f"\nThis is an automated notification — passwords are not sent by email.\n"
    )
    notify_async(smtp_cfg_to_data(cfg), recipients, subject, body)
