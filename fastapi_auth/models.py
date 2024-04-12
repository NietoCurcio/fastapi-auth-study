from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str
    extra_data: dict[str, str] | None = None
    scopes: list[str] = []


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    admin: bool | None = None


class UserInDB(User):
    hashed_password: str
