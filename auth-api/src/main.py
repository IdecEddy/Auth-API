#!/usr/bin/env python3.12
from loggingconf import setup_logging, logger


def main():
    setup_logging()
    logger.info("Hello World")
    logger.warning("This is bad")

if __name__ == "__main__":
    main()

