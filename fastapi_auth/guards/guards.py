from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt
from pydantic import ValidationError

from fastapi_auth.config import ALGORITHM, SECRET_KEY
from fastapi_auth.db import get_user
from fastapi_auth.exceptions import Unauthorized
from fastapi_auth.models import TokenData, User

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/users/login",
    scopes={"me": "Read information about the current user.", "items": "Read items."},
)


async def _decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        token_scopes = payload.get("scopes", [])
        return TokenData(scopes=token_scopes, username=username)
    except JWTError:
        raise Unauthorized(detail="Signature is invalid or token is expired")
    except ValidationError:
        raise Unauthorized(detail="Could not validate credentials")


def _validate_token_scopes(token_data: TokenData, security_scopes: SecurityScopes):
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": f'Bearer scope="{security_scopes.scope_str}"'},
            )


async def _get_user_by_username(username: str) -> User:
    user = get_user(username=username)
    if user is None:
        raise Unauthorized(detail="Could not validate credentials")
    return user


async def get_current_user(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
) -> User:
    token_data = await _decode_token(token)
    _validate_token_scopes(token_data, security_scopes)
    return await _get_user_by_username(token_data.username)


class Guards:
    async def get_current_active_user(
        self,
        current_user: Annotated[User, Security(get_current_user, scopes=["me"])],
    ):
        if current_user.disabled:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
        return current_user

    async def get_current_admin_user(
        self,
        current_user: Annotated[User, Depends(get_current_user)],
    ):
        if not current_user.admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions"
            )
        return current_user


guards = Guards()
