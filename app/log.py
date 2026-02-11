import logging
import graypy
import os
from datetime import datetime


def setup_custom_logger(name, log_method: str, log_level: str, graylog_host: str = None, graylog_port: int = None):
    logger = logging.getLogger(name)
    log_levels = {'debug': 10, 'info': 20, 'warning': 30, 'error': 40, 'critical': 50}
    logger.setLevel(log_levels.get(log_level, 20))

    if log_method == "file":
        log_file_name = f"tebe_backend_{datetime.now().strftime('%Y_%m_%d')}.log"
        log_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "logs", log_file_name)

        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                            filename=log_path,
                            filemode='a')

    elif log_method == "graylog":
        handler = graypy.GELFUDPHandler(graylog_host, graylog_port)
        for h in logger.handlers:

            if isinstance(h, graypy.GELFUDPHandler):
                return logger

        logger.addHandler(handler)

        logger.propagate = False

    return logger
