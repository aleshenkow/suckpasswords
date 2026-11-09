from sqlalchemy.orm import Session

from ..models import AuditLog


def log_action(
    db: Session,
    username: str,
    action: str,
    resource_type: str = "",
    resource_id: str | int = "",
    details: str = "",
) -> None:
    """Append an audit-log row. Caller is responsible for db.commit()."""
    db.add(
        AuditLog(
            username=username or "",
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id != "" else "",
            details=details or "",
        )
    )
