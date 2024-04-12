from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext

from fastapi_auth.config import ALGORITHM, SECRET_KEY, TOKEN_EXPIRE_MINUTES
from fastapi_auth.db import get_user
from fastapi_auth.models import Token

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    def _authenticate_user(self, username: str, password: str):
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        if not pwd_context.verify(password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        return user

    def _create_access_token(self, data: dict):
        expiration_time = datetime.now(UTC) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
        payload = {**data, "exp": expiration_time}
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    def authenticate(self, form_data: OAuth2PasswordRequestForm) -> Token:
        user = self._authenticate_user(form_data.username, form_data.password)
        access_token = self._create_access_token({"sub": user.username, "scopes": form_data.scopes})
        return Token(access_token=access_token, token_type="bearer")


auth_service = AuthService()
