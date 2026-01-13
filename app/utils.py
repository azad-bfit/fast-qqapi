import os
from datetime import datetime, timedelta
from typing import Union, Any
from jose import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --------------- Password Hashing -------------------

def hash_password(pwd: str) -> str:
    return pwd_context.hash(pwd)

def verify_password(plain_pwd: str, hased_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hased_pwd)

# ---------------- JWT Configration -----------------

ACCESS_TOKEN_EXPIRE_MINUTES = 30 # 30 min
REFRASH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']   # should be kept secret
JWT_REFRESH_SECRET_KEY = os.environ['JWT_REFRESH_SECRET_KEY']    # should be kept secret

def create_access_token(
    subject: Union[str, Any],
    expires_delta: int = None,
) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": expire,
        "type": "access",
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=ALGORITHM,
    )


def create_refresh_token(
    subject: Union[str, Any],
    expires_delta: int = None,
) -> str:
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

    payload: dict[str, Any] = {
        "sub": str(subject),
        "exp": expire,
        "type": "refresh",
    }

    return jwt.encode(
        payload,
        settings.JWT_REFRESH_SECRET_KEY,
        algorithm=ALGORITHM,
    )
