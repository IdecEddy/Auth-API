import logging.config
import logging.handlers
import atexit
import pathlib
import json

logger = logging.getLogger("logging_sandbox")


def setup_logging():
    config_file = pathlib.Path("logging_configs/logging-conf.json")
    with open(config_file) as f_in:
        config = json.load(f_in)

    logging.config.dictConfig(config)
    queue_handler = logging.getHandlerByName("queue_handler")
    if queue_handler is not None:
        queue_handler.listener.start()
        atexit.register(queue_handler.listener.stop)

    return logger


if __name__ == "__main__":
    pass
