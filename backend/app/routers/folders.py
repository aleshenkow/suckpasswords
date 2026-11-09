from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import assert_admin, get_current_user
from ..models import Entry, Folder, User
from ..schemas import (
    FolderCreate,
    FolderDelete,
    FolderMove,
    FolderRename,
    FolderResponse,
)
from ..services.audit import log_action
from ..services.folders import (
    assert_valid_parent,
    collect_descendants,
    folder_descendants_map,
    is_descendant,
)

router = APIRouter()


def _folder_response(folder: Folder) -> FolderResponse:
    return FolderResponse(
        id=folder.id, name=folder.name, parent_id=folder.parent_id, icon=folder.icon, is_system=folder.is_system
    )


@router.post("/folders", response_model=FolderResponse)
def create_folder(
    payload: FolderCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> FolderResponse:
    assert_admin(user)
    assert_valid_parent(db, payload.parent_id)

    folder = Folder(name=payload.name.strip(), parent_id=payload.parent_id, icon=(payload.icon or "📁"))
    db.add(folder)
    db.flush()
    log_action(db, user.username, "folder.create", "folder", folder.id, f"name={folder.name!r}")
    db.commit()
    db.refresh(folder)
    return _folder_response(folder)


@router.get("/folders", response_model=list[FolderResponse])
def list_folders(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[FolderResponse]:
    _ = user
    folders = db.scalars(select(Folder).order_by(Folder.parent_id, Folder.name)).all()
    # System folders (General) always first
    folders = sorted(folders, key=lambda f: (0 if f.is_system else 1, f.name))
    return [
        FolderResponse(id=f.id, name=f.name, parent_id=f.parent_id, icon=f.icon, is_system=f.is_system) for f in folders
    ]


@router.put("/folders/{folder_id}/rename", response_model=FolderResponse)
def rename_folder(
    folder_id: int,
    payload: FolderRename,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> FolderResponse:
    assert_admin(user)

    folder = db.scalar(select(Folder).where(Folder.id == folder_id))
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System folders cannot be renamed")

    old_name = folder.name
    folder.name = payload.name.strip()
    if payload.icon is not None:
        folder.icon = payload.icon or "📁"
    log_action(
        db,
        user.username,
        "folder.rename",
        "folder",
        folder.id,
        f"{old_name!r} -> {folder.name!r}",
    )
    db.commit()
    db.refresh(folder)
    return _folder_response(folder)


@router.patch("/folders/{folder_id}/move", response_model=FolderResponse)
def move_folder(
    folder_id: int,
    payload: FolderMove,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> FolderResponse:
    assert_admin(user)

    folder = db.scalar(select(Folder).where(Folder.id == folder_id))
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System folders cannot be moved")

    if payload.parent_id == folder_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Folder cannot be moved into itself")

    assert_valid_parent(db, payload.parent_id)

    if payload.parent_id is not None:
        parent_map = folder_descendants_map(db)
        parent_map[folder.id] = payload.parent_id
        if is_descendant(parent_map, payload.parent_id, folder.id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Folder cannot be moved into its descendant",
            )

    old_parent = folder.parent_id
    folder.parent_id = payload.parent_id
    log_action(
        db,
        user.username,
        "folder.move",
        "folder",
        folder.id,
        f"parent {old_parent} -> {payload.parent_id}",
    )
    db.commit()
    db.refresh(folder)
    return _folder_response(folder)


@router.delete("/folders/{folder_id}")
def delete_folder(
    folder_id: int,
    payload: FolderDelete | None = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str | int]:
    assert_admin(user)

    folder = db.scalar(select(Folder).where(Folder.id == folder_id))
    if not folder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    if folder.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System folders cannot be deleted")

    strategy = payload.strategy if payload else "move_children_to_root"

    if strategy == "delete_recursive":
        parent_map = folder_descendants_map(db)
        descendants = collect_descendants(parent_map, folder.id)
        target_ids = [folder.id, *descendants]

        affected_entries = db.scalars(select(Entry).where(Entry.folder_id.in_(target_ids))).all()
        for entry in affected_entries:
            entry.folder_id = None

        folders_to_delete = db.scalars(select(Folder).where(Folder.id.in_(target_ids))).all()
        deleted_count = len(folders_to_delete)
        for target in folders_to_delete:
            db.delete(target)

        log_action(
            db,
            user.username,
            "folder.delete",
            "folder",
            folder_id,
            f"recursive deleted={deleted_count} reassigned_entries={len(affected_entries)}",
        )
        db.commit()
        return {
            "message": "Folder tree deleted",
            "deleted_folders": deleted_count,
            "reassigned_entries": len(affected_entries),
        }

    children = db.scalars(select(Folder).where(Folder.parent_id == folder.id)).all()
    for child in children:
        child.parent_id = None

    entries_in_folder = db.scalars(select(Entry).where(Entry.folder_id == folder.id)).all()
    for entry in entries_in_folder:
        entry.folder_id = None

    folder_name = folder.name
    db.delete(folder)
    log_action(
        db,
        user.username,
        "folder.delete",
        "folder",
        folder_id,
        f"name={folder_name!r} moved_children={len(children)} reassigned_entries={len(entries_in_folder)}",
    )
    db.commit()
    return {
        "message": "Folder deleted and children moved to root",
        "moved_children": len(children),
        "reassigned_entries": len(entries_in_folder),
    }
