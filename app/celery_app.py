import os
import configparser
from celery import Celery
from app import log
from app.extensions import db
from celery.signals import after_setup_logger, after_setup_task_logger


celery = Celery(__name__)
_flask_app = None


def _ensure_worker_logging_configured():
    try:
        cfg = configparser.ConfigParser(delimiters=('=',), interpolation=None)
        configpath = os.path.join(os.path.dirname(__file__), "config.ini")
        cfg.read(configpath, encoding="utf-8")

        log.setup_custom_logger(
            "root",
            cfg.get("Logging", "method", fallback="file"),
            cfg.get("Logging", "level", fallback="info"),
            graylog_host=cfg.get("Logging", "graylog_host", fallback=None),
            graylog_port=cfg.getint("Logging", "graylog_port", fallback=0),
        )
    except Exception as e:
        _ = e
        pass


@after_setup_logger.connect
def _setup_celery_root_logger(celery_logger, *args, **kwargs):
    _ensure_worker_logging_configured()


@after_setup_task_logger.connect
def _setup_celery_task_logger(celery_task_logger, *args, **kwargs):
    _ensure_worker_logging_configured()


def init_celery(flask_app):
    celery.conf.update(
        broker_url=flask_app.config["CELERY_BROKER_URL"],
        result_backend=flask_app.config["CELERY_RESULT_BACKEND"],
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        broker_connection_retry_on_startup=True,
        worker_hijack_root_logger=False,
        worker_redirect_stdouts=False,
    )

    class FlaskTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return super().__call__(*args, **kwargs)

        def after_return(self, status, retval, task_id, args, kwargs, einfo):
            try:
                db.session.remove()
            except Exception as e:
                _ = e
                pass
            return super().after_return(status, retval, task_id, args, kwargs, einfo)

    celery.Task = FlaskTask
    return celery
