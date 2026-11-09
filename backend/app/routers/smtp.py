import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import assert_admin, get_current_user
from ..models import SmtpConfig, User
from ..schemas import (
    SmtpConfigResponse,
    SmtpConfigSave,
    SmtpTestRequest,
)
from ..security import encrypt_secret
from ..services.audit import log_action
from ..services.smtp import get_smtp_row, smtp_cfg_to_data, smtp_send

router = APIRouter()


# ── SMTP / Email notifications ─────────────────────────────────────────────────


def _smtp_row_to_response(cfg: SmtpConfig) -> SmtpConfigResponse:
    return SmtpConfigResponse(
        enabled=cfg.enabled,
        host=cfg.host,
        port=cfg.port,
        use_tls=cfg.use_tls,
        use_ssl=cfg.use_ssl,
        anonymous=cfg.anonymous,
        username=cfg.username,
        password_set=bool(cfg.password),
        from_email=cfg.from_email,
        from_name=cfg.from_name,
        notify_on_create=cfg.notify_on_create,
        notify_on_update=cfg.notify_on_update,
        notify_on_delete=cfg.notify_on_delete,
    )


@router.get("/admin/smtp", response_model=SmtpConfigResponse)
def get_smtp_config(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> SmtpConfigResponse:
    assert_admin(user)
    cfg = get_smtp_row(db)
    if cfg is None:
        cfg = SmtpConfig(id=1)
        db.add(cfg)
        db.commit()
    return _smtp_row_to_response(cfg)


@router.put("/admin/smtp", response_model=SmtpConfigResponse)
def save_smtp_config(
    payload: SmtpConfigSave,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SmtpConfigResponse:
    assert_admin(user)
    cfg = get_smtp_row(db)
    if cfg is None:
        cfg = SmtpConfig(id=1)
        db.add(cfg)

    cfg.enabled = payload.enabled
    cfg.host = payload.host.strip()
    cfg.port = int(payload.port or 587)
    cfg.use_tls = payload.use_tls
    cfg.use_ssl = payload.use_ssl
    cfg.anonymous = payload.anonymous
    cfg.username = payload.username.strip()
    if payload.password:  # empty/None = keep existing
        cfg.password = encrypt_secret(payload.password)
    cfg.from_email = payload.from_email.strip()
    cfg.from_name = payload.from_name.strip() or "SuckPasswords"
    cfg.notify_on_create = payload.notify_on_create
    cfg.notify_on_update = payload.notify_on_update
    cfg.notify_on_delete = payload.notify_on_delete

    log_action(
        db,
        user.username,
        "smtp.save",
        "smtp",
        "",
        f"enabled={cfg.enabled} host={cfg.host}:{cfg.port} anonymous={cfg.anonymous}",
    )
    db.commit()
    return _smtp_row_to_response(cfg)


@router.post("/admin/smtp/test")
def test_smtp(
    payload: SmtpTestRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    assert_admin(user)
    cfg = get_smtp_row(db)
    if cfg is None or not cfg.host:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SMTP is not configured")
    to_email = (payload.to_email or "").strip() or user.email
    if not to_email or "@" not in to_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recipient email is invalid")
    try:
        smtp_send(
            smtp_cfg_to_data(cfg),
            [to_email],
            "[SuckPasswords] SMTP test message",
            "This is a test email from SuckPasswords. If you received it, SMTP is configured correctly.\n",
        )
    except Exception as exc:
        logging.exception("SMTP test failed: %s", exc)
        raw = str(exc)
        # Detect SSH banner on wrong port
        if "OpenSSH" in raw or ("(-1," in raw and b"SSH" in repr(exc).encode(errors="ignore")):
            detail = (
                "Connected to an SSH server instead of SMTP. "
                "Check that the SMTP host and port are correct (common ports: 25, 465, 587)."
            )
        elif "Connection refused" in raw:
            detail = f"Connection refused — verify the SMTP host and port. ({raw})"
        elif "timed out" in raw.lower():
            detail = f"Connection timed out — the server may be unreachable or the port is blocked. ({raw})"
        elif "SSL" in raw or "ssl" in raw:
            detail = f"SSL/TLS error — try toggling the SSL option. ({raw})"
        else:
            detail = raw
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)
    log_action(db, user.username, "smtp.test", "smtp", "", f"to={to_email}")
    db.commit()
    return {"message": f"Test email sent to {to_email}"}
