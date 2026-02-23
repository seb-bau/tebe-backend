from flask import render_template, request, jsonify, flash, redirect, url_for
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
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import logging
from flask import session
from sqlalchemy import func

from app.microsoft_auth import (
    validate_id_token,
    build_authorize_url,
    exchange_code_for_tokens,
    generate_state_nonce,
    normalize_email_from_claims,
    get_ms_config
)

# ACHTUNG: BEI NEUER VERSION ANPASSEN
APP_VERSION_MIN = 1
APP_VERSION_MAX = 0

logger = logging.getLogger()


def check_version(version, pdata: dict) -> bool:
    try:
        tversion = int(version)
    except (ValueError, TypeError):
        logger.error(f"check_version: '{version}' is not numeric for login with user '{pdata.get('email')}'")
        return False

    if APP_VERSION_MIN and tversion < APP_VERSION_MIN:
        return False
    if APP_VERSION_MAX and tversion > APP_VERSION_MAX:
        return False
    return True


def register_routes_auth(app):
    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")
        app_version = request.args.get("app_version")

        if not check_version(app_version, data):
            return jsonify({"msg": "app version mismatch"}), 403

        if not email or not password:
            return jsonify({"msg": "email and password required"}), 400

        user = db.session.query(User).filter_by(email=email).first()

        if not user:
            return jsonify({"msg": "bad credentials"}), 401

        if not user.is_active:
            return jsonify({"msg": "user is disabled"}), 403

        if not user or not user.check_password(password):
            return jsonify({"msg": "bad credentials"}), 401

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        access_expires = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())
        refresh_expires = int(current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds())

        user.last_action = datetime.now()
        user.last_version = app_version
        db.session.commit()

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_expires_in": access_expires,
            "refresh_expires_in": refresh_expires
        }), 200

    @app.route("/.well-known/app-auth-config", methods=["GET"])
    def app_auth_config():
        cfg = get_ms_config(current_app)
        if cfg is None:
            return jsonify({"msg": "microsoft auth not configured"}), 404
        return jsonify({
            "tenant_id": cfg["tenant_id"],
            "client_id": cfg["client_id"]
        }), 200

    @app.route("/auth/microsoft", methods=["POST"])
    def login_microsoft():
        cfg = get_ms_config(current_app)
        if cfg is None:
            return jsonify({"msg": "microsoft auth not configured"}), 404

        data = request.get_json() or {}
        id_token = data.get("id_token")
        app_version = request.args.get("app_version")

        if not id_token:
            return jsonify({"msg": "id_token required"}), 400

        if not check_version(app_version, {"email": ""}):
            logger.error(f"login_microsoft: App version mismatch")
            return jsonify({"msg": "app version mismatch"}), 403

        try:
            claims = validate_id_token(
                id_token=id_token,
                tenant_id=cfg["tenant_id"],
                client_id=cfg["client_id"]
            )
        except Exception as e:
            logger.error(f"login_microsoft: invalid id token: {str(e)}")
            return jsonify({"msg": "invalid id token"}), 401

        oid = claims.get("oid")
        email = (claims.get("email") or claims.get("preferred_username") or claims.get("upn") or "").strip().lower()

        user = db.session.query(User).filter_by(microsoft_tid=cfg["tenant_id"], microsoft_oid=oid).first()

        if user is None and email:
            user = (
                db.session.query(User)
                .filter(func.lower(User.email) == email)
                .first()
            )
            if user and (not user.microsoft_oid and not user.microsoft_tid):
                user.microsoft_tid = cfg["tenant_id"]
                user.microsoft_oid = oid
                db.session.commit()

        if not user:
            logger.error(f"login_microsoft: User '{claims.get('email')}' not found in database")
            return jsonify({"msg": "user not found"}), 401

        if not user.is_active:
            return jsonify({"msg": "user is disabled"}), 403

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        access_expires = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())
        refresh_expires = int(current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds())

        user.last_ip = request.environ['REMOTE_ADDR']
        user.last_action = datetime.now()
        user.last_version = app_version
        db.session.commit()

        logger.info(f"login_microsoft: User '{user.email}' logged in with IP {user.last_ip}")

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_expires_in": access_expires,
            "refresh_expires_in": refresh_expires
        }), 200

    @app.route("/auth/refresh", methods=["POST"])
    @jwt_required(refresh=True)
    def refresh():
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        app_version = request.args.get("app_version")
        data = {
            "email": user.email
        }

        if not check_version(app_version, data):
            return jsonify({"msg": "app version mismatch"}), 403

        if not user or not user.is_active:
            return jsonify({"msg": "user disabled or not found"}), 403
        user.last_action = datetime.now()
        db.session.commit()
        access_expires = int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())
        new_access_token = create_access_token(identity=str(current_user_id))
        return jsonify({
            "access_token": new_access_token,
            "access_expires_in": access_expires
        }), 200

    @app.route("/auth/logout", methods=["POST"])
    @jwt_required()
    def logout():
        jti = get_jwt()["jti"]
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if not user or not user.is_active:
            return jsonify({"msg": "user disabled or not found"}), 403
        db.session.commit()
        return jsonify({"msg": "access token revoked"}), 200

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")

            if not email or not password:
                flash("Bitte E-Mail und Passwort eingeben.", "danger")
                return redirect(url_for("admin_login"))

            user = db.session.query(User).filter_by(email=email).first()

            if not user or not user.check_password(password):
                flash("Ungültige Zugangsdaten.", "danger")
                return redirect(url_for("admin_login"))

            if not user.is_active:
                flash("Benutzer ist deaktiviert.", "danger")
                return redirect(url_for("admin_login"))

            if not user.is_admin:
                flash("Kein Zugriff auf den Admin-Bereich.", "danger")
                return redirect(url_for("admin_login"))

            login_user(user)
            flash("Erfolgreich eingeloggt.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))

        return render_template("admin/login.html")

    @app.route("/admin/logout")
    @login_required
    def admin_logout():
        logout_user()
        flash("Du wurdest ausgeloggt.", "info")
        return redirect(url_for("admin_login"))

    @app.route("/admin/login/microsoft", methods=["GET"])
    def admin_login_microsoft():
        cfg = get_ms_config(current_app)
        client_secret = current_app.config["INI_CONFIG"].get("MicrosoftAuth", "client_secret", fallback=None)
        if cfg is None or not client_secret:
            flash("Microsoft-Login ist nicht konfiguriert.", "danger")
            return redirect(url_for("admin_login"))

        state, nonce = generate_state_nonce()
        session["ms_state"] = state
        session["ms_nonce"] = nonce

        redirect_uri = url_for("admin_auth_microsoft_callback", _external=True)
        url = build_authorize_url(
            tenant_id=cfg["tenant_id"],
            client_id=cfg["client_id"],
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
        )
        return redirect(url)

    @app.route("/admin/auth/microsoft/callback", methods=["GET"])
    def admin_auth_microsoft_callback():
        cfg = get_ms_config(current_app)
        if cfg is None:
            flash("Microsoft-Login ist nicht konfiguriert.", "danger")
            return redirect(url_for("admin_login"))

        if request.args.get("error"):
            flash("Microsoft-Login abgebrochen oder fehlgeschlagen.", "danger")
            return redirect(url_for("admin_login"))

        state = request.args.get("state", "")
        if not state or state != session.get("ms_state"):
            flash("Ungültiger Login-Status (state).", "danger")
            return redirect(url_for("admin_login"))

        code = request.args.get("code", "")
        if not code:
            flash("Kein Authorization Code erhalten.", "danger")
            return redirect(url_for("admin_login"))

        client_secret = current_app.config.get("INI_CONFIG").get("MicrosoftAuth", "client_secret", fallback=None)
        if not client_secret:
            flash("Dieser Server erlaubt keine Anmeldung über Microsoft.", "danger")
            return redirect(url_for("admin_login"))

        redirect_uri = url_for("admin_auth_microsoft_callback", _external=True)

        try:
            tokens = exchange_code_for_tokens(
                tenant_id=cfg["tenant_id"],
                client_id=cfg["client_id"],
                client_secret=client_secret,
                code=code,
                redirect_uri=redirect_uri,
            )
        except Exception as e:
            flash("Microsoft Token-Austausch fehlgeschlagen.", "danger")
            logger.error(f"admin_auth_microsoft_callback: Token exchange failed: {str(e)}")
            return redirect(url_for("admin_login"))

        id_token = tokens.get("id_token")
        if not id_token:
            flash("Kein ID Token von Microsoft erhalten.", "danger")
            return redirect(url_for("admin_login"))

        try:
            claims = validate_id_token(
                id_token=id_token,
                tenant_id=cfg["tenant_id"],
                client_id=cfg["client_id"],
            )
        except Exception as e:
            logger.error(f"admin_auth_microsoft_callback: token error: {str(e)}")
            flash("Ungültiges Microsoft Token.", "danger")
            return redirect(url_for("admin_login"))

        expected_nonce = session.get("ms_nonce")
        if expected_nonce and claims.get("nonce") != expected_nonce:
            flash("Ungültiger Login-Status (nonce).", "danger")
            return redirect(url_for("admin_login"))

        oid = claims.get("oid")
        email = normalize_email_from_claims(claims)

        user = db.session.query(User).filter_by(
            microsoft_tid=cfg["tenant_id"],
            microsoft_oid=oid
        ).first()

        if user is None and email:
            user = db.session.query(User).filter(func.lower(User.email) == email).first()
            if user and (not user.microsoft_oid and not user.microsoft_tid):
                user.microsoft_tid = cfg["tenant_id"]
                user.microsoft_oid = oid
                db.session.commit()

        if not user:
            flash("Benutzer nicht gefunden.", "danger")
            return redirect(url_for("admin_login"))

        if not user.is_active:
            flash("Benutzer ist deaktiviert.", "danger")
            return redirect(url_for("admin_login"))

        if not user.is_admin:
            flash("Kein Zugriff auf den Admin-Bereich.", "danger")
            return redirect(url_for("admin_login"))

        login_user(user)

        session.pop("ms_state", None)
        session.pop("ms_nonce", None)

        flash("Erfolgreich mit Microsoft eingeloggt.", "success")
        return redirect(url_for("index"))
