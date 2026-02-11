import os
import configparser
from celery import Celery
from app import log
from app.extensions import db
from celery.signals import after_setup_logger, worker_process_init
import logging


celery = Celery(__name__)
_flask_app = None
_worker_logging_configured = False


def _ensure_worker_logging_configured():
    global _flask_app, _worker_logging_configured

    # Wenn Flower/Worker Celery importiert, bevor init_celery() lief: nichts tun
    if _flask_app is None:
        return

    # Schon konfiguriert? Dann nicht nochmal Handler anhängen
    if _worker_logging_configured:
        return

    try:
        with _flask_app.app_context():
            cfg = configparser.ConfigParser(delimiters=("=",), interpolation=None)
            configpath = os.path.join(os.path.dirname(__file__), "config.ini")
            cfg.read(configpath, encoding="utf-8")

            log.setup_custom_logger(
                "root",
                cfg.get("Logging", "method", fallback="file"),
                cfg.get("Logging", "level", fallback="info"),
                graylog_host=cfg.get("Logging", "graylog_host", fallback=None),
                graylog_port=cfg.getint("Logging", "graylog_port", fallback=0),
            )

        # Celery Logger nicht ins root “durchreichen”, sonst ggf. doppelt
        logging.getLogger("celery").propagate = False

        _worker_logging_configured = True
    except Exception:
        # kein print -> sonst Spam
        return


@after_setup_logger.connect
def _setup_celery_root_logger(logger=None, *args, **kwargs):
    _ensure_worker_logging_configured()


@worker_process_init.connect
def _on_worker_process_init(**kwargs):
    global _worker_logging_configured
    _worker_logging_configured = False
    _ensure_worker_logging_configured()


def init_celery(flask_app):
    global _flask_app
    _flask_app = flask_app
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
        worker_enable_remote_control=True,
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
