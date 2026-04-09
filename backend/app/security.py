import secrets
import string
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from cryptography.fernet import Fernet
from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _build_fernet() -> Fernet:
    raw = settings.app_data_encryption_key or settings.app_secret_key
    digest = sha256(raw.encode("utf-8")).digest()
    key = Fernet.generate_key() if not raw else None
    if key is None:
        import base64

        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


fernet = _build_fernet()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.app_access_token_expire_minutes)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.app_secret_key, algorithm="HS256")


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.app_secret_key, algorithms=["HS256"])
        return payload.get("sub")
    except JWTError:
        return None


def generate_password(length: int = 24) -> str:
    if length < 12:
        length = 12
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def encrypt_secret(value: str) -> str:
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
