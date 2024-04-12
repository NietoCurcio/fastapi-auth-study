from fastapi import FastAPI

from fastapi_auth.api.router import api_router

app = FastAPI()

app.include_router(api_router, prefix="/api")
