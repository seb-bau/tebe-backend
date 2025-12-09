from flask import render_template, request, jsonify, flash, abort, redirect, url_for
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
from functools import wraps


def register_routes(app):
    def admin_required(view_func):
        @wraps(view_func)
        @login_required
        def wrapped_view(*args, **kwargs):
            if not getattr(current_user, "is_admin", False):
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped_view

    @app.route("/")
    @admin_required
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

    # User-Liste
    @app.route("/admin/users")
    @admin_required
    def admin_users_list():
        users = User.query.order_by(User.email.asc()).all()
        return render_template("admin/users_list.html", users=users)

    # Neuen Benutzer anlegen
    @app.route("/admin/users/create", methods=["GET", "POST"])
    @admin_required
    def admin_users_create():
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            is_active = bool(request.form.get("is_active"))
            is_admin = bool(request.form.get("is_admin"))

            if not email or not password:
                flash("E-Mail und Passwort sind Pflichtfelder.", "danger")
                return redirect(url_for("admin_users_create"))

            if User.query.filter_by(email=email).first():
                flash("Es existiert bereits ein Benutzer mit dieser E-Mail.", "danger")
                return redirect(url_for("admin_users_create"))

            user = User(
                email=email,
                is_active=is_active,
                is_admin=is_admin
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Benutzer wurde erstellt.", "success")
            return redirect(url_for("admin_users_list"))

        return render_template("admin/user_form.html", user=None)

    # Benutzer bearbeiten
    @app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_users_edit(user_id):
        user = User.query.get_or_404(user_id)

        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")  # optional
            is_active = bool(request.form.get("is_active"))
            is_admin = bool(request.form.get("is_admin"))

            if not email:
                flash("E-Mail darf nicht leer sein.", "danger")
                return redirect(url_for("admin_users_edit", user_id=user.id))

            if User.query.filter(User.email == email, User.id != user.id).first():
                flash("Es existiert bereits ein anderer Benutzer mit dieser E-Mail.", "danger")
                return redirect(url_for("admin_users_edit", user_id=user.id))

            user.email = email
            user.is_active = is_active
            user.is_admin = is_admin

            if password:
                user.set_password(password)

            db.session.commit()
            flash("Benutzer wurde aktualisiert.", "success")
            return redirect(url_for("admin_users_list"))

        return render_template("admin/user_form.html", user=user)

    # Benutzer löschen
    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @admin_required
    def admin_users_delete(user_id):
        user = User.query.get_or_404(user_id)

        if user.id == current_user.id:
            flash("Du kannst dich nicht selbst löschen.", "danger")
            return redirect(url_for("admin_users_list"))

        db.session.delete(user)
        db.session.commit()
        flash("Benutzer wurde gelöscht.", "info")
        return redirect(url_for("admin_users_list"))

