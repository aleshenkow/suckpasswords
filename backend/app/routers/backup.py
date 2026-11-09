import csv as csv_module
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import assert_admin, get_current_user
from ..models import Entry, User
from ..services.audit import log_action
from ..services.backup import (
    backup_decrypt,
    backup_encrypt,
    entries_to_rows,
    import_rows,
)

router = APIRouter()


# ── Backup endpoint ──────────────────────────────────────────────────────────


@router.post("/admin/backup")
def create_backup(
    password: str = Form(..., min_length=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    assert_admin(user)
    rows = entries_to_rows(db)
    payload = json.dumps(
        {
            "version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entries": rows,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    encrypted = backup_encrypt(payload, password)
    log_action(db, user.username, "backup.create", "backup", "", f"entries={len(rows)}")
    db.commit()
    return StreamingResponse(
        io.BytesIO(encrypted),
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=suckpasswords.spbackup"},
    )


@router.post("/admin/restore")
async def restore_backup(
    password: str = Form(..., min_length=1),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    assert_admin(user)
    raw = await file.read()
    try:
        plaintext = backup_decrypt(raw, password)
        data = json.loads(plaintext.decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    rows = data.get("entries", [])
    # Full restore: delete all existing entries, then re-import
    for e in db.scalars(select(Entry)).all():
        db.delete(e)
    db.flush()
    imported, skipped = import_rows(db, rows)
    log_action(
        db,
        user.username,
        "backup.restore",
        "backup",
        "",
        f"imported={imported} skipped={skipped}",
    )
    db.commit()
    return {"message": "Restore complete", "imported": imported, "skipped": skipped}


# ── Export CSV ──────────────────────────────────────────────────────────────


@router.get("/admin/export/csv")
def export_csv(
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    assert_admin(user)
    buf = io.StringIO()
    fields = ["title", "login", "password", "url", "description", "icon", "level", "entry_type_code", "folder_name"]
    writer = csv_module.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    # Example row so the user understands the format
    writer.writerow(
        {
            "title": "Example — My GitHub",
            "login": "username",
            "password": "YourPasswordHere",
            "url": "https://github.com",
            "description": "Optional notes",
            "icon": "🐙",
            "level": "general",
            "entry_type_code": "password",
            "folder_name": "General",
        }
    )
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=suckpasswords_import_template.csv"},
    )


# ── Import CSV ──────────────────────────────────────────────────────────────


@router.post("/admin/import/csv")
async def import_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    assert_admin(user)
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")  # handle BOM from Excel
        reader = csv_module.DictReader(io.StringIO(text))
        rows = list(reader)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid CSV: {exc}")
    imported, skipped = import_rows(db, rows)
    log_action(
        db,
        user.username,
        "csv.import",
        "entry",
        "",
        f"imported={imported} skipped={skipped}",
    )
    db.commit()
    return {"message": "Import complete", "imported": imported, "skipped": skipped}
