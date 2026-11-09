from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Folder


def assert_valid_parent(db: Session, parent_id: int | None) -> None:
    if parent_id is None:
        return
    parent = db.scalar(select(Folder).where(Folder.id == parent_id))
    if parent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent folder not found")


def folder_descendants_map(db: Session) -> dict[int, int | None]:
    rows = db.scalars(select(Folder)).all()
    return {row.id: row.parent_id for row in rows}


def is_descendant(parent_map: dict[int, int | None], node_id: int, maybe_ancestor_id: int) -> bool:
    cursor = parent_map.get(node_id)
    while cursor is not None:
        if cursor == maybe_ancestor_id:
            return True
        cursor = parent_map.get(cursor)
    return False


def collect_descendants(parent_map: dict[int, int | None], root_id: int) -> list[int]:
    children_by_parent: dict[int, list[int]] = {}
    for node_id, parent_id in parent_map.items():
        if parent_id is None:
            continue
        children_by_parent.setdefault(parent_id, []).append(node_id)

    descendants: list[int] = []
    stack: list[int] = [root_id]
    while stack:
        current = stack.pop()
        direct_children = children_by_parent.get(current, [])
        descendants.extend(direct_children)
        stack.extend(direct_children)
    return descendants
