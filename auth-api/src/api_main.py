from fastapi import FastAPI
from routers.auth import router as auth
from fastapi.middleware.cors import CORSMiddleware


def create_app() -> FastAPI:
    app = FastAPI()
    # Define a list of allowed origins for CORS
    # For development, you might allow localhost origins
    # Replace "http://localhost:3000" with the actual origin of your frontend app
    origins = [
        "http://localhost:3000",  # Adjust this to match your frontend's URL
        "https://localhost:3000", # If your frontend is served over HTTPS
        "*"  
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,  # Allows specified origins
        allow_credentials=True,
        allow_methods=["*"],  # Allows all methods
        allow_headers=["*"],  # Allows all headers
    )

    app.include_router(auth)
    return app