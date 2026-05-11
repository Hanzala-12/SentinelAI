from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from backend.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class AuthService:
    def hash_password(self, password: str) -> str:
        # bcrypt has a 72-byte limit; truncate if necessary
        truncated = password[:72]
        return pwd_context.hash(truncated)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        # truncate to match hash_password behavior
        truncated = plain_password[:72]
        return pwd_context.verify(truncated, hashed_password)

    def create_access_token(self, subject: str) -> str:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
        payload = {'sub': subject, 'exp': expire}
        return jwt.encode(payload, settings.secret_key, algorithm='HS256')

    def decode_access_token(self, token: str) -> dict:
        payload = jwt.decode(token, settings.secret_key, algorithms=['HS256'])
        if not isinstance(payload, dict):
            raise jwt.InvalidTokenError('Invalid token payload')
        return payload
