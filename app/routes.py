from flask import render_template, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from app.models import User, TokenBlocklist
from app.extensions import db
from flask import current_app


def register_routes(app):
    @app.route("/")
    def index():
        return render_template('index.html')

    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json() or {}

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"msg": "email and password required"}), 400

        user = db.session.query(User).filter_by(email=email).first()

        if not user.is_active:
            return jsonify({"msg": "user is disabled"}), 403

        if not user or not user.check_password(password):
            return jsonify({"msg": "bad credentials"}), 401

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        access_expires = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())
        refresh_expires = int(current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds())

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_expires_in": access_expires,
            "refresh_expires_in": refresh_expires
        }), 200

    @app.route("/protected", methods=["GET"])
    @jwt_required()
    def protected():
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        if not user or not user.is_active:
            return jsonify({"msg": "user disabled"}), 403
        return jsonify({"msg": f"Hello user {user_id}"}), 200

    @app.route("/auth/refresh", methods=["POST"])
    @jwt_required(refresh=True)
    def refresh():
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if not user or not user.is_active:
            return jsonify({"msg": "user disabled or not found"}), 403
        access_expires = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())
        new_access_token = create_access_token(identity=str(current_user_id))
        return jsonify({
            "access_token": new_access_token,
            "access_expires_in": access_expires
        }), 200

    # -------------------------
    # LOGOUT: Invalidate access token
    # -------------------------
    @app.route("/auth/logout", methods=["POST"])
    @jwt_required()
    def logout():
        jti = get_jwt()["jti"]
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
        return jsonify({"msg": "access token revoked"}), 200

    # -------------------------
    # LOGOUT REFRESH: Invalidate refresh token
    # -------------------------
    @app.route("/auth/logout_refresh", methods=["POST"])
    @jwt_required(refresh=True)
    def logout_refresh():
        jti = get_jwt()["jti"]
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
        return jsonify({"msg": "refresh token revoked"}), 200
