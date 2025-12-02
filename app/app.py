import os
import configparser

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from app import log
from .extensions import db, migrate, bcrypt, jwt
from datetime import timedelta


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

    db.init_app(tapp)
    migrate.init_app(tapp, db)
    bcrypt.init_app(tapp)
    jwt.init_app(tapp)

    tapp.wsgi_app = ProxyFix(tapp.wsgi_app, x_proto=1, x_host=1)

    from app.routes import register_routes
    from app.cli import register_cli_commands

    register_routes(tapp)
    register_cli_commands(tapp)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        _ = jwt_header
        from app.models import TokenBlocklist
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist).filter_by(jti=jti).first()
        return token is not None

    return tapp


app = create_app()
