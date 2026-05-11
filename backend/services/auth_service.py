from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from backend.config import get_settings

settings = get_settings()


class AuthService:
    @staticmethod
    def _normalize_password(password: str) -> bytes:
        # bcrypt accepts at most 72 bytes, so we truncate at the byte level.
        return password.encode("utf-8")[:72]

    def hash_password(self, password: str) -> str:
        normalized = self._normalize_password(password)
        return bcrypt.hashpw(normalized, bcrypt.gensalt()).decode("utf-8")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        try:
            normalized = self._normalize_password(plain_password)
            return bcrypt.checkpw(normalized, hashed_password.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    def create_access_token(self, subject: str) -> str:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
        payload = {'sub': subject, 'exp': expire}
        return jwt.encode(payload, settings.secret_key, algorithm='HS256')

    def decode_access_token(self, token: str) -> dict:
        payload = jwt.decode(token, settings.secret_key, algorithms=['HS256'])
        if not isinstance(payload, dict):
            raise jwt.InvalidTokenError('Invalid token payload')
        return payload
