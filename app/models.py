from .extensions import db, bcrypt
from sqlalchemy import func
from flask_login import UserMixin


class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())


class Geolocation(db.Model):
    __tablename__ = "geolocation"

    id = db.Column(db.Integer, primary_key=True)
    building_id = db.Column(db.Integer, nullable=False)
    building_idnum = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.String(50), nullable=False)
    lon = db.Column(db.String(50), nullable=False)
