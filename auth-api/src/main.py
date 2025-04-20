#!/usr/bin/env python3.12
from loggingconf import setup_logging
from api_main import create_app
from utils.db import init_db
import uvicorn


init_db()
app = create_app()


def main():
    setup_logging()
    init_db()
    uvicorn.run("main:create_app()", host="127.0.0.1", port=8000, reload=True)


if __name__ == "__main__":
    app = main()
