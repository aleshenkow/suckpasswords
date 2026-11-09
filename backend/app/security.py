import base64
import hashlib
import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import jwt
from cryptography.fernet import Fernet
from passlib.context import CryptContext

from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _data_secret() -> str:
    return settings.app_data_encryption_key or settings.app_secret_key


def _build_legacy_fernet() -> Fernet:
    """Key derivation used before v2 (plain SHA-256). Kept only to decrypt existing data."""
    raw = _data_secret()
    if not raw:
        return Fernet(Fernet.generate_key())
    return Fernet(base64.urlsafe_b64encode(sha256(raw.encode("utf-8")).digest()))


def _build_fernet() -> Fernet:
    """v2: scrypt-derived key. The secret is a server-side key, so a fixed application salt is used."""
    raw = _data_secret() or base64.urlsafe_b64encode(os.urandom(32)).decode()
    key = hashlib.scrypt(
        raw.encode("utf-8"), salt=b"suckpasswords/data-key/v2", n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024
    )
    return Fernet(base64.urlsafe_b64encode(key))


_V2_PREFIX = "v2:"
legacy_fernet = _build_legacy_fernet()
fernet = _build_fernet()
_DUMMY_HASH = pwd_context.hash(secrets.token_urlsafe(16))


def burn_password_check(password: str) -> None:
    """Spend the same time as a real hash check (used for unknown users to avoid a timing oracle)."""
    pwd_context.verify(password, _DUMMY_HASH)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    minutes = expires_minutes if expires_minutes is not None else settings.app_access_token_expire_minutes
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.app_secret_key, algorithm="HS256")


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.app_secret_key, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def generate_password(length: int = 24) -> str:
    if length < 12:
        length = 12
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def encrypt_secret(value: str) -> str:
    return _V2_PREFIX + fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def is_legacy_ciphertext(value: str) -> bool:
    return bool(value) and not value.startswith(_V2_PREFIX)


def decrypt_secret(value: str) -> str:
    if value.startswith(_V2_PREFIX):
        return fernet.decrypt(value[len(_V2_PREFIX) :].encode("utf-8")).decode("utf-8")
    return legacy_fernet.decrypt(value.encode("utf-8")).decode("utf-8")
