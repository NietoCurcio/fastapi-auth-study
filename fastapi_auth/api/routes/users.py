from typing import Annotated

from fastapi import APIRouter, Depends, Security
from fastapi.security import OAuth2PasswordRequestForm

from fastapi_auth.guards.guards import get_current_user, guards
from fastapi_auth.models import Token, User
from fastapi_auth.services import auth_service

router = APIRouter()


@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    return auth_service.authenticate(form_data)


@router.get("/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(guards.get_current_active_user)],
):
    return current_user


@router.get("/me/items/")
async def read_own_items(
    current_user: Annotated[User, Security(guards.get_current_active_user, scopes=["items"])],
):
    return [{"item_id": "Foo", "owner": current_user.username}]


@router.get("/status/")
async def read_system_status(current_user: Annotated[User, Depends(get_current_user)]):
    return {"status": "ok"}


@router.get("/admin/")
async def read_admin_status(
    current_user: Annotated[User, Depends(guards.get_current_admin_user)],
):
    """
    We don't strictly need to use JWT with scopes,
    a dependency guard is enough, instead of creating ['admin'] scope
    """
    return {"status": "ok"}
