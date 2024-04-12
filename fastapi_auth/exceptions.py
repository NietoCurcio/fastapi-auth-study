from fastapi import HTTPException, status


class Unauthorized(HTTPException):
    def __init__(self, detail: str = "Unauthorized", headers: dict = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers=headers,
        )
