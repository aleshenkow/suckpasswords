from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Entry, EntryType, Folder, User
from ..schemas import (
    EntryCreate,
    EntryResponse,
    EntryUpdate,
)
from ..security import decrypt_secret, encrypt_secret, generate_password
from ..services.access import user_access_levels
from ..services.audit import log_action
from ..services.smtp import notify_entry_event

router = APIRouter()


@router.post("/entries", response_model=EntryResponse)
def create_entry(
    payload: EntryCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> EntryResponse:
    entry_type = db.scalar(select(EntryType).where(EntryType.code == payload.entry_type_code))
    if not entry_type:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry type not found")

    accessible_levels = user_access_levels(db, user)
    entry_level = payload.level or "general"
    if entry_level not in accessible_levels:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry level")

    if payload.folder_id is not None:
        folder = db.scalar(select(Folder).where(Folder.id == payload.folder_id))
        if folder is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")

    entry = Entry(
        folder_id=payload.folder_id,
        entry_type_id=entry_type.id,
        title=payload.title,
        login=payload.login,
        password=encrypt_secret(payload.password),
        url=payload.url,
        description=payload.description,
        icon=payload.icon,
        level=entry_level,
        created_by=user.username,
    )
    db.add(entry)
    db.flush()
    log_action(
        db,
        user.username,
        "entry.create",
        "entry",
        entry.id,
        f"title={entry.title!r} type={entry_type.code} level={entry.level}",
    )
    db.commit()
    db.refresh(entry)
    notify_entry_event(db, entry, entry_type.code, user.username, "created")

    return EntryResponse(
        id=entry.id,
        folder_id=entry.folder_id,
        entry_type_code=entry_type.code,
        title=entry.title,
        login=entry.login,
        password=payload.password,
        url=entry.url,
        description=entry.description,
        icon=entry.icon,
        level=entry.level,
        created_by=entry.created_by,
    )


@router.get("/entries", response_model=list[EntryResponse])
def list_entries(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[EntryResponse]:
    accessible_levels = user_access_levels(db, user)
    if not accessible_levels:
        return []
    entries = db.scalars(select(Entry).where(Entry.level.in_(accessible_levels)).order_by(Entry.title)).all()
    type_codes = {t.id: t.code for t in db.scalars(select(EntryType)).all()}
    response: list[EntryResponse] = []
    for entry in entries:
        code = type_codes.get(entry.entry_type_id)
        if code is None:
            continue
        response.append(
            EntryResponse(
                id=entry.id,
                folder_id=entry.folder_id,
                entry_type_code=code,
                title=entry.title,
                login=entry.login,
                password="",  # revealed on demand via GET /entries/{id}/password (audited)
                url=entry.url,
                description=entry.description,
                icon=entry.icon,
                level=entry.level,
                created_by=entry.created_by,
            )
        )
    return response


@router.get("/entries/{entry_id}/password")
def reveal_entry_password(
    entry_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    entry = db.scalar(select(Entry).where(Entry.id == entry_id))
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")
    if entry.level not in user_access_levels(db, user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry")
    log_action(db, user.username, "entry.reveal", "entry", entry.id, f"title={entry.title!r} level={entry.level}")
    db.commit()
    return {"password": decrypt_secret(entry.password)}


@router.put("/entries/{entry_id}", response_model=EntryResponse)
def update_entry(
    entry_id: int,
    payload: EntryUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EntryResponse:
    entry = db.scalar(select(Entry).where(Entry.id == entry_id))
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")

    entry_type = db.scalar(select(EntryType).where(EntryType.id == entry.entry_type_id))
    accessible_levels = user_access_levels(db, user)
    if entry.level not in accessible_levels:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry")

    if payload.entry_type_code:
        new_type = db.scalar(select(EntryType).where(EntryType.code == payload.entry_type_code))
        if new_type is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry type not found")
        entry.entry_type_id = new_type.id
        entry_type = new_type

    if payload.folder_id is not None:
        folder = db.scalar(select(Folder).where(Folder.id == payload.folder_id))
        if folder is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    entry.folder_id = payload.folder_id

    if payload.title:
        entry.title = payload.title
    if payload.login is not None:
        entry.login = payload.login
    plain_pw = ""
    if payload.password:
        entry.password = encrypt_secret(payload.password)
        plain_pw = payload.password
    if payload.url is not None:
        entry.url = payload.url
    if payload.description is not None:
        entry.description = payload.description
    if payload.icon is not None:
        entry.icon = payload.icon
    if payload.level:
        if payload.level not in accessible_levels:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry level")
        entry.level = payload.level

    log_action(
        db,
        user.username,
        "entry.update",
        "entry",
        entry.id,
        f"title={entry.title!r} type={entry_type.code} level={entry.level}",
    )
    db.commit()
    db.refresh(entry)
    notify_entry_event(db, entry, entry_type.code, user.username, "updated")
    return EntryResponse(
        id=entry.id,
        folder_id=entry.folder_id,
        entry_type_code=entry_type.code,
        title=entry.title,
        login=entry.login,
        password=plain_pw,
        url=entry.url,
        description=entry.description,
        icon=entry.icon,
        level=entry.level,
        created_by=entry.created_by,
    )


@router.delete("/entries/{entry_id}")
def delete_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    entry = db.scalar(select(Entry).where(Entry.id == entry_id))
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")
    accessible_levels = user_access_levels(db, user)
    if entry.level not in accessible_levels:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No access to this entry")
    entry_type = db.scalar(select(EntryType).where(EntryType.id == entry.entry_type_id))
    snapshot_title = entry.title
    snapshot_level = entry.level
    snapshot_type_code = entry_type.code if entry_type else ""
    # Build a detached copy for notification (entry will be deleted before commit)
    notify_entry = Entry(
        title=snapshot_title,
        level=snapshot_level,
        login="",
        password="",
        entry_type_id=entry.entry_type_id,
    )
    db.delete(entry)
    log_action(
        db,
        user.username,
        "entry.delete",
        "entry",
        entry_id,
        f"title={snapshot_title!r} level={snapshot_level}",
    )
    db.commit()
    notify_entry_event(db, notify_entry, snapshot_type_code, user.username, "deleted")
    return {"message": "Deleted"}


@router.get("/password/generate")
def password_generate(length: int = 24, user: User = Depends(get_current_user)) -> dict[str, str]:
    _ = user
    return {"password": generate_password(length)}
