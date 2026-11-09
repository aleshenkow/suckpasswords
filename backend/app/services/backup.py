import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Entry, EntryType, Folder
from ..security import decrypt_secret, encrypt_secret

_BACKUP_MAGIC = b"SPBK"
_BACKUP_VERSION = b"\x01"
_PBKDF2_ITERATIONS = 260_000


def backup_encrypt(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return _BACKUP_MAGIC + _BACKUP_VERSION + salt + nonce + ct


def backup_decrypt(data: bytes, password: str) -> bytes:
    if len(data) < 5 + 32 + 12 or data[:4] != _BACKUP_MAGIC or data[4:5] != _BACKUP_VERSION:
        raise ValueError("Invalid or corrupted backup file")
    salt, nonce, ct = data[5:37], data[37:49], data[49:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted backup")


def entries_to_rows(db: Session) -> list[dict]:
    """Return all entries as plain-text dicts (passwords decrypted)."""
    folder_map = {f.id: f.name for f in db.scalars(select(Folder)).all()}
    type_map = {t.id: t.code for t in db.scalars(select(EntryType)).all()}
    rows = []
    for e in db.scalars(select(Entry)).all():
        rows.append(
            {
                "title": e.title,
                "login": e.login,
                "password": decrypt_secret(e.password),
                "url": e.url,
                "description": e.description,
                "icon": e.icon,
                "level": e.level,
                "entry_type_code": type_map.get(e.entry_type_id, "password"),
                "folder_name": folder_map.get(e.folder_id, "") if e.folder_id else "",
            }
        )
    return rows


def import_rows(db: Session, rows: list[dict]) -> tuple[int, int]:
    """Create entries from a list of dicts. Returns (imported, skipped)."""
    folder_cache: dict[str, int] = {}
    type_cache: dict[str, int] = {}

    def get_folder_id(name: str) -> int | None:
        if not name:
            # default to General system folder
            general = db.scalar(select(Folder).where(Folder.is_system.is_(True)))
            return general.id if general else None
        if name in folder_cache:
            return folder_cache[name]
        f = db.scalar(select(Folder).where(Folder.name == name))
        if f is None:
            f = Folder(name=name)
            db.add(f)
            db.flush()
        folder_cache[name] = f.id
        return f.id

    def get_type_id(code: str) -> int | None:
        code = code or "password"
        if code in type_cache:
            return type_cache[code]
        t = db.scalar(select(EntryType).where(EntryType.code == code))
        if t is None:
            return None
        type_cache[code] = t.id
        return t.id

    imported = skipped = 0
    for row in rows:
        title = (row.get("title") or "").strip()
        password = (row.get("password") or "").strip()
        if not title or not password:
            skipped += 1
            continue
        type_id = get_type_id(row.get("entry_type_code", "password"))
        if type_id is None:
            skipped += 1
            continue
        folder_id = get_folder_id(row.get("folder_name", ""))
        db.add(
            Entry(
                folder_id=folder_id,
                entry_type_id=type_id,
                title=title,
                login=row.get("login", ""),
                password=encrypt_secret(password),
                url=row.get("url", ""),
                description=row.get("description", ""),
                icon=row.get("icon", ""),
                level=row.get("level", "general"),
            )
        )
        imported += 1
    return imported, skipped
