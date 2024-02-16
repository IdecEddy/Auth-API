from fastapi import FastAPI
from routers.auth import router as auth


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth)
    return app
