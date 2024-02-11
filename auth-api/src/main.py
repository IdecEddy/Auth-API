#!/usr/bin/env python3.12
from loggingconf import setup_logging, logger
from api_main import create_app


app = create_app() 

def main():
    setup_logging()
    app = create_app()

if __name__ == "__main__":
    app = main()

