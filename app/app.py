import os
import configparser

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from app import log
from .extensions import db, migrate, bcrypt, jwt, login_manager
from datetime import timedelta
from app.celery_app import init_celery


def create_app():
    tapp = Flask(__name__)

    config = configparser.ConfigParser(delimiters=('=',), interpolation=None)
    configpath = os.path.join(tapp.root_path, '..', 'config.ini')
    config.read(configpath, encoding='utf-8')

    tapp.secret_key = config.get('General', 'app_secret')

    tapp.config['SQLALCHEMY_DATABASE_URI'] = config.get('Database', 'connection_uri')
    tapp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    tapp.config["JWT_SECRET_KEY"] = config.get('General', 'jwt_secret')
    tapp.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
    tapp.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=365)
    tapp.config['INI_CONFIG'] = config
    tapp.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    _logger = log.setup_custom_logger(
        'root',
        config.get('Logging', 'method', fallback='file'),
        config.get('Logging', 'level', fallback='info'),
        graylog_host=config.get('Logging', 'graylog_host', fallback=None),
        graylog_port=config.getint('Logging', 'graylog_port', fallback=0),
    )

    try:
        if config.getboolean('Debug', 'store_payloads', fallback=False):
            tapp.config["STORE_PAYLOADS"] = True
    except Exception as e:
        _ = e
        pass

    if config.getboolean('Debug', 'demo_mode', fallback=False):
        tapp.config['DEMO_MODE'] = True
        tapp.config['DEMO_CUR_DATA'] = os.path.join(tapp.root_path, "demo_current_data.json")
        tapp.config['DEMO_FLOOR_PLAN'] = os.path.join(tapp.root_path, "demo_floor_plan.png")
        tapp.config['DEMO_SEARCH'] = os.path.join(tapp.root_path, "demo_search.json")
        tapp.config['DEMO_CONTACTS'] = os.path.join(tapp.root_path, "demo_contacts.json")
        if (os.path.exists(tapp.config['DEMO_CUR_DATA']) and
                os.path.exists(tapp.config['DEMO_FLOOR_PLAN']) and
                os.path.exists(tapp.config['DEMO_SEARCH']) and
                os.path.exists(tapp.config['DEMO_CONTACTS'])):
            _logger.info(f"STARTING IN DEMO MODE")
        else:
            _logger.critical(f"MISSING DEMO FILE!")
    else:
        tapp.config['DEMO_MODE'] = False

    db.init_app(tapp)
    migrate.init_app(tapp, db)
    bcrypt.init_app(tapp)
    jwt.init_app(tapp)
    login_manager.init_app(tapp)

    login_manager.login_view = "admin_login"
    login_manager.login_message_category = "warning"

    tapp.wsgi_app = ProxyFix(tapp.wsgi_app, x_proto=1, x_host=1)

    from app.routes_auth import register_routes_auth
    from app.routes_web import register_routes_web
    from app.routes_api_meta import register_routes_api_meta
    from app.routes_api_media import register_routes_api_media
    from app.routes_api_contacts import register_routes_api_contacts
    from app.routes_api_inventory import register_routes_api_inventory
    from app.routes_api_masterdata import register_routes_api_masterdata
    from app.routes_api_ticket import register_routes_api_ticket
    from app.cli import register_cli_commands

    register_routes_auth(tapp)
    register_routes_web(tapp)
    register_routes_api_meta(tapp)
    register_routes_api_media(tapp)
    register_routes_api_contacts(tapp)
    register_routes_api_inventory(tapp)
    register_routes_api_masterdata(tapp)
    register_routes_api_ticket(tapp)
    register_cli_commands(tapp)

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        _ = jwt_header
        from app.models import TokenBlocklist
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist).filter_by(jti=jti).first()
        return token is not None

    default_broker_url = "redis://localhost:6379/0"
    default_result_backend = "redis://localhost:6379/1"
    try:
        celery_broker_url = config.get("Celery", "broker_url", fallback=default_broker_url)
        celery_result_backend = config.get("Celery", "result_backend", fallback=default_result_backend)
    except KeyError:
        celery_broker_url = default_broker_url
        celery_result_backend = default_result_backend

    tapp.config.setdefault("CELERY_BROKER_URL", celery_broker_url)
    tapp.config.setdefault("CELERY_RESULT_BACKEND", celery_result_backend)

    celery = init_celery(tapp)

    from app.tasks import register_tasks
    register_tasks(celery)

    return tapp


app = create_app()
