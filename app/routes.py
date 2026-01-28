from flask import render_template, request, jsonify, flash, abort, redirect, url_for
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from wowipy.models import Result

from app.erp import create_facility, create_component, edit_component
from wowipy.wowipy import WowiPy, ComponentElement, MediaData, LicenseAgreement
import wowipy.models
from app.models import User, TokenBlocklist, FacilityCatalogItem, ComponentCatalogItem, UnderComponentItem, Geolocation
from app.models import EventItem, FacilityItem
from app.extensions import db
from flask import current_app, send_file
from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps
from sqlalchemy import or_, inspect, func
from app.erp import with_wowi_retry
from app.geo import get_buildings_in_radius_m, haversine_distance_m
from wowicache.models import WowiCache, Building, UseUnit, Contract, Contractor, Person
from datetime import datetime, timedelta, time, timezone
import logging
import numbers
import os
import tempfile
import uuid
from werkzeug.utils import secure_filename


# ACHTUNG: BEI NEUER VERSION ANPASSEN
APP_VERSION_MIN = 1
APP_VERSION_MAX = 0

LIMIT_MAX = 20
LIMIT_DEFAULT = 20


logger = logging.getLogger('root')


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


def is_numeric(value):
    return isinstance(value, numbers.Number)


def get_bool_arg(name: str):
    return request.args.get(name, "").lower() in ("1", "true", "yes", "on")


def has_table(table_name: str) -> bool:
    try:
        return inspect(db.engine).has_table(table_name)
    except Exception as e:
        print(str(e))
        return False


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
        now = datetime.now(timezone.utc)
        year_start = now - timedelta(days=364)
        last_7 = now - timedelta(days=7)
        last_30 = now - timedelta(days=30)

        total_users = db.session.query(func.count(User.id)).scalar() or 0
        active_users = db.session.query(func.count(User.id)).filter(User.is_active.is_(True)).scalar() or 0

        total_events = db.session.query(func.count(EventItem.id)).scalar() or 0
        total_changes = (
            db.session.query(func.count(EventItem.id))
            .filter(EventItem.action.in_(["create", "edit"]))
            .scalar()
            or 0
        )

        active_users_7d = (
            db.session.query(func.count(func.distinct(EventItem.user_id)))
            .filter(EventItem.stamp >= last_7)
            .scalar()
            or 0
        )
        active_users_30d = (
            db.session.query(func.count(func.distinct(EventItem.user_id)))
            .filter(EventItem.stamp >= last_30)
            .scalar()
            or 0
        )

        changes_7d = (
            db.session.query(func.count(EventItem.id))
            .filter(EventItem.action.in_(["create", "edit"]))
            .filter(EventItem.stamp >= last_7)
            .scalar()
            or 0
        )
        changes_30d = (
            db.session.query(func.count(EventItem.id))
            .filter(EventItem.action.in_(["create", "edit"]))
            .filter(EventItem.stamp >= last_30)
            .scalar()
            or 0
        )

        daily_rows = (
            db.session.query(func.date(EventItem.stamp).label("d"), func.count(EventItem.id).label("c"))
            .filter(EventItem.action.in_(["create", "edit"]))
            .filter(EventItem.stamp >= year_start)
            .group_by("d")
            .order_by("d")
            .all()
        )

        daily_map = {str(d): int(c) for (d, c) in daily_rows if d is not None}

        labels = []
        values = []
        for i in range(365):
            day = (year_start.date() + timedelta(days=i)).isoformat()
            labels.append(day)
            values.append(daily_map.get(day, 0))

        action_rows_30d = (
            db.session.query(EventItem.action, func.count(EventItem.id))
            .filter(EventItem.stamp >= last_30)
            .group_by(EventItem.action)
            .order_by(func.count(EventItem.id).desc())
            .all()
        )
        action_labels = [a or "unknown" for (a, _) in action_rows_30d]
        action_values = [int(c) for (_, c) in action_rows_30d]

        top_users_30d = (
            db.session.query(EventItem.user_name, func.count(EventItem.id).label("c"))
            .filter(EventItem.action.in_(["create", "edit"]))
            .filter(EventItem.stamp >= last_30)
            .group_by(EventItem.user_name)
            .order_by(func.count(EventItem.id).desc(), EventItem.user_name.asc())
            .limit(10)
            .all()
        )
        top_users_rows = [{"user_name": u, "changes": int(c)} for (u, c) in top_users_30d]

        recent_changes = (
            db.session.query(EventItem)
            .filter(EventItem.action.in_(["create", "edit"]))
            .order_by(EventItem.stamp.desc(), EventItem.id.desc())
            .limit(20)
            .all()
        )

        return render_template(
            "index.html",
            stats={
                "total_users": total_users,
                "active_users": active_users,
                "total_events": total_events,
                "total_changes": total_changes,
                "active_users_7d": active_users_7d,
                "active_users_30d": active_users_30d,
                "changes_7d": changes_7d,
                "changes_30d": changes_30d,
            },
            chart_year={"labels": labels, "values": values},
            chart_actions_30d={"labels": action_labels, "values": action_values},
            top_users_rows=top_users_rows,
            recent_changes=recent_changes,
        )

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

    # -------------------------
    # LOGOUT: Invalidate access token
    # -------------------------
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
            name = request.form.get("name")
            password = request.form.get("password")
            is_active = bool(request.form.get("is_active"))
            is_admin = bool(request.form.get("is_admin"))

            if not email or not password:
                flash("E-Mail und Passwort sind Pflichtfelder.", "danger")
                return redirect(url_for("admin_users_create"))

            if User.query.filter_by(email=email).first():
                flash("Es existiert bereits ein Benutzer mit dieser E-Mail.", "danger")
                return redirect(url_for("admin_users_create"))

            # noinspection PyArgumentList
            user = User(
                email=email,
                is_active=is_active,
                is_admin=is_admin,
                name=name
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
            name = request.form.get("name")
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
            user.name = name
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

    # -------------------------
    # FacilityCatalogItem (Ausstattungsgruppen)
    # -------------------------
    @app.route("/admin/facilities")
    @admin_required
    def admin_facilities_list():
        """List facility catalog items with search, filters and pagination."""
        # Basic query parameters for UX
        page = request.args.get("page", 1, type=int)
        q = (request.args.get("q") or "").strip()
        status_filter = request.args.get("status")  # "active", "inactive" or None

        query = FacilityCatalogItem.query

        # Apply search filter (case-insensitive) – limited to a few fields
        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    FacilityCatalogItem.name.ilike(like),
                    FacilityCatalogItem.custom_name.ilike(like),
                    FacilityCatalogItem.status_name.ilike(like),
                )
            )

        # Filter by enabled status
        if status_filter == "active":
            query = query.filter_by(enabled=True)
        elif status_filter == "inactive":
            query = query.filter_by(enabled=False)

        # Default ordering
        query = query.order_by(FacilityCatalogItem.name.asc())

        # Pagination – moderate page size for performance
        pagination = query.paginate(page=page, per_page=25, error_out=False)
        facilities = pagination.items

        return render_template(
            "admin/facilities_list.html",
            facilities=facilities,
            pagination=pagination,
            q=q,
            status_filter=status_filter,
        )

    @app.route("/admin/facilities/<int:facility_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_facilities_edit(facility_id):
        """Edit custom data of a single facility catalog item."""
        facility = FacilityCatalogItem.query.get_or_404(facility_id)

        if request.method == "POST":
            view_folded = bool(request.form.get("view_folded"))
            custom_name = request.form.get("custom_name") or None

            facility.custom_name = custom_name
            facility.view_folded = view_folded

            db.session.commit()
            flash("Ausstattungsgruppe wurde aktualisiert.", "success")
            return redirect(url_for("admin_facilities_list"))

        return render_template("admin/facility_form.html", facility=facility)

    # -------------------------
    # ComponentCatalogItem (Merkmale)
    # -------------------------
    @app.route("/admin/components")
    @admin_required
    def admin_components_list():
        """List component catalog items with search, filters and pagination."""
        page = request.args.get("page", 1, type=int)
        q = (request.args.get("q") or "").strip()
        status_filter = request.args.get("status")  # "active", "inactive" or None

        query = ComponentCatalogItem.query.join(FacilityCatalogItem, isouter=True)

        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    ComponentCatalogItem.name.ilike(like),
                    ComponentCatalogItem.custom_name.ilike(like),
                    ComponentCatalogItem.comment.ilike(like),
                    FacilityCatalogItem.name.ilike(like),
                    FacilityCatalogItem.custom_name.ilike(like),
                )
            )

        if status_filter == "active":
            query = query.filter(ComponentCatalogItem.enabled.is_(True))
        elif status_filter == "inactive":
            query = query.filter(ComponentCatalogItem.enabled.is_(False))

        query = query.order_by(ComponentCatalogItem.name.asc())

        pagination = query.paginate(page=page, per_page=25, error_out=False)
        components = pagination.items

        return render_template(
            "admin/components_list.html",
            components=components,
            pagination=pagination,
            q=q,
            status_filter=status_filter,
        )

    @app.route("/admin/components/<int:component_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_components_edit(component_id):
        """Edit custom data of a single component catalog item."""
        component = ComponentCatalogItem.query.get_or_404(component_id)

        if request.method == "POST":
            enabled = bool(request.form.get("enabled"))
            is_bool = bool(request.form.get("is_bool"))
            single_under_component = bool(request.form.get("single_under_component"))
            hide_quantity = bool(request.form.get("hide_quantity"))
            custom_name = request.form.get("custom_name") or None

            if is_bool and single_under_component:
                flash("Wenn bool ausgewählt wird, kann nicht zeitgleich Single Sub aktiviert sein.",
                      category="error")
                return redirect(url_for("admin_components_list"))
            component.enabled = enabled
            component.custom_name = custom_name
            component.is_bool = is_bool
            component.single_under_component = single_under_component
            component.hide_quantity = hide_quantity

            db.session.commit()
            flash("Merkmal wurde aktualisiert.", "success")
            return redirect(url_for("admin_components_list"))

        return render_template("admin/component_form.html", component=component)

    # -------------------------
    # UnderComponentItem (Merkmalausprägungen)
    # -------------------------
    @app.route("/admin/under_components")
    @admin_required
    def admin_under_components_list():
        """List under component items with search, filters and pagination."""
        page = request.args.get("page", 1, type=int)
        q = (request.args.get("q") or "").strip()
        status_filter = request.args.get("status")  # "active", "inactive" or None

        query = UnderComponentItem.query

        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    UnderComponentItem.name.ilike(like),
                    UnderComponentItem.custom_name.ilike(like),
                )
            )

        if status_filter == "active":
            query = query.filter(UnderComponentItem.enabled.is_(True))
        elif status_filter == "inactive":
            query = query.filter(UnderComponentItem.enabled.is_(False))

        query = query.order_by(UnderComponentItem.name.asc())

        pagination = query.paginate(page=page, per_page=25, error_out=False)
        under_components = pagination.items

        return render_template(
            "admin/under_components_list.html",
            under_components=under_components,
            pagination=pagination,
            q=q,
            status_filter=status_filter,
        )

    @app.route("/admin/under_components/<int:under_component_id>/edit", methods=["GET", "POST"])
    @admin_required
    def admin_under_components_edit(under_component_id):
        """Edit custom data of a single under component item."""
        under_component = UnderComponentItem.query.get_or_404(under_component_id)

        if request.method == "POST":
            enabled = bool(request.form.get("enabled"))
            custom_name = request.form.get("custom_name") or None

            under_component.enabled = enabled
            under_component.custom_name = custom_name

            db.session.commit()
            flash("Merkmalausprägung wurde aktualisiert.", "success")
            return redirect(url_for("admin_under_components_list"))

        return render_template(
            "admin/under_component_form.html",
            under_component=under_component,
        )

    @app.route("/app/use-unit/data/current/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_current_data(use_unit_id):
        def _do_app_uu_current_data(wowi: WowiPy, uu_id: int):
            components = wowi.get_components(use_unit_id=uu_id)
            retval_existing = []
            retval_missing = []
            found_types = []
            component: ComponentElement
            for component in components:
                comp_cat_item = db.session.get(ComponentCatalogItem, component.component_catalog_id)
                if not comp_cat_item:
                    logger.error(f"app_uu_current_data: Could not get component catalog item with id "
                                 f"'{component.component_catalog_id}' for use_unit_id '{use_unit_id}' for user "
                                 f"'todo'")
                    return jsonify({"msg": f"Missing component catalog item '{component.component_catalog_id}'"}), 500
                if not comp_cat_item.enabled:
                    continue
                if comp_cat_item.under_components:
                    under_components = []
                    for uc in comp_cat_item.under_components:
                        is_selected = False
                        if component.under_components:
                            is_selected = any(c.id_ == uc.id for c in component.under_components)
                        under_components.append({
                            "id": uc.id,
                            "name": uc.name,
                            "selected": is_selected
                        })
                else:
                    under_components = None

                fac_item = db.session.get(FacilityItem, component.facility_id)
                fac_cat = db.session.get(FacilityCatalogItem, fac_item.facility_catalog_item_id)
                retval_existing.append({
                    "id": component.id_,
                    "name": component.name,
                    "component_catalog_id": component.component_catalog_id,
                    "quantitiy": component.count,
                    "unit": comp_cat_item.quantity_type_name,
                    "under_components": under_components,
                    "facility_cat_id": component.facility_id,
                    "facility_cat_name": fac_item.name,
                    "facility_folded": fac_cat.view_folded,
                    "is_bool": comp_cat_item.is_bool,
                    "single_under_component": comp_cat_item.single_under_component,
                    "hide_quantity": comp_cat_item.hide_quantity,
                    "comment": component.comment
                })
                found_types.append(comp_cat_item.id)

            comp_cat = db.session.query(ComponentCatalogItem).filter(ComponentCatalogItem.enabled.is_(True)).all()
            cat_item: ComponentCatalogItem
            for cat_item in comp_cat:
                fac_cat = db.session.get(FacilityCatalogItem, cat_item.facility_catalog_item_id)
                if cat_item.id not in found_types:
                    under_components = []
                    for uc in cat_item.under_components:
                        under_components.append({
                            "id": uc.id,
                            "name": uc.name
                        })
                    retval_missing.append({
                        "id": cat_item.id,
                        "name": cat_item.name,
                        "unit": cat_item.quantity_type_name,
                        "under_components": under_components,
                        "facility_cat_id": cat_item.facility_catalog_item_id,
                        "facility_cat_name": cat_item.facility.name,
                        "facility_folded": fac_cat.view_folded,
                        "is_bool": cat_item.is_bool,
                        "single_under_component": cat_item.single_under_component,
                        "hide_quantity": cat_item.hide_quantity
                    })
            return {
                "existing_items": retval_existing,
                "missing_items": retval_missing
            }
        oretval = with_wowi_retry(_do_app_uu_current_data, uu_id=use_unit_id)
        return jsonify(oretval)

    @app.route("/app/use-unit/data/write/<int:use_unit_id>", methods=["POST"])
    @jwt_required()
    def app_uu_write_data(use_unit_id):
        def _do_app_uu_write_data(wowi: WowiPy, uu_id: int):
            data = request.get_json()
            print(data)
            components_updated = 0
            components_created = 0
            facilities_created = 0
            components_deleted = 0
            for entry in data:
                if not entry.get("component_catalog_id"):
                    return jsonify({"msg": "missing component_catalog_id"}), 400
                comp_cat_item = db.session.get(ComponentCatalogItem, entry.get("component_catalog_id"))
                if not comp_cat_item:
                    return jsonify({"msg": "unknown component_catalog_id"}), 400

                if not comp_cat_item.enabled:
                    return jsonify({"msg": "component_catalog_id disabled"}), 400

                if not is_numeric(entry.get("quantity")):
                    return jsonify({"msg": "quantity has to be numeric"}), 400

                comment = entry.get("comment")

                psub = entry.get("sub_components") or []
                if not entry.get("component_id"):
                    if entry.get("is_unknown"):
                        # Wenn es die Komponente noch nicht gab und sie unbekannt istm können wir sie direkt
                        # ignorieren
                        continue
                    # Wenn der Client die component_id nicht mitsendet, heißt das in der Regel, dass diese Komponente
                    # noch nicht für die UseUnit existiert.
                    # TODO: In der Zukunft könnte man an dieser Stelle prüfen, ob das wirklich der Fall ist
                    # TODO: Es ist ggf. ein Performance-Problem, die Facilities der UU hier jedes mal abzufragen
                    uu_facilities = wowi.get_facilities(use_unit_id=uu_id)
                    uu_facility = None
                    for fac_entry in uu_facilities:
                        if fac_entry.facility_catalog_id == comp_cat_item.facility_catalog_item_id:
                            uu_facility = fac_entry.id_
                            break
                    if not uu_facility:
                        uu_facility = create_facility(wowi, comp_cat_item.facility_catalog_item_id, uu_id)
                        facilities_created += 1
                    if not uu_facility:
                        return abort(500, "Error while creating facility.")
                    print(f"sub {psub}")
                    current_user_id = int(get_jwt_identity())
                    user: User
                    user = User.query.get(current_user_id)
                    user.last_action = datetime.now()
                    db.session.commit()
                    component_id = create_component(wowi,
                                                    component_catalog_id=comp_cat_item.id,
                                                    facility_id=uu_facility,
                                                    count=int(entry.get("quantity")),
                                                    psub_components=psub,
                                                    puser=user,
                                                    puu_id=uu_id,
                                                    comment=comment)
                    components_created += 1
                    if not component_id:
                        return abort(500, "Error while creating component")
                    logger.info(f"app_uu_write_data: Created component {component_id}")
                else:
                    unknown = bool(entry.get("is_unknown"))
                    edit_component(wowi, entry.get("component_id"), int(entry.get("quantity")), psub_components=psub,
                                   unknown=unknown, comment=comment)
                    if not unknown:
                        components_updated += 1
                    else:
                        components_deleted += 1

            return jsonify({
                "facilities_created": facilities_created,
                "components_created": components_created,
                "components_updated": components_updated,
                "components_deleted": components_deleted
            })
        oretval = with_wowi_retry(_do_app_uu_write_data, uu_id=use_unit_id)
        return oretval

    def building_ids_from_radius(lat, lon, radius_m):
        locations_found = get_buildings_in_radius_m(lat, lon, radius_m=radius_m)
        return {item["building_id"] for item in locations_found if item.get("building_id")}

    def apply_fulltext(query, fulltext: str):
        ft = (fulltext or "").strip()
        if not ft:
            return query

        like = f"%{ft}%"
        return query.filter(or_(
            Building.street_complete.ilike(like),
            Building.street.ilike(like),
            Building.house_number.ilike(like),
            Building.postcode.ilike(like),
            Building.town.ilike(like),
        ))

    @app.route("/app/use-unit/photos", methods=["POST"])
    @jwt_required()
    def route_use_unit_photos():
        photo = request.files.get("photo")
        use_unit_id_raw = request.form.get("use_unit_id")

        if photo is None or not photo.filename:
            return jsonify({"status": "error", "message": "Missing photo"}), 400

        try:
            use_unit_id = int(use_unit_id_raw)
        except (TypeError, ValueError):
            return jsonify({"status": "error", "message": "Invalid use_unit_id"}), 400

        temp_dir = os.path.join(tempfile.gettempdir(), "tebe_use_unit_photos")
        os.makedirs(temp_dir, exist_ok=True)

        original_name = secure_filename(photo.filename) or "photo"
        stored_name = f"{use_unit_id}_{uuid.uuid4().hex}_{original_name}"
        stored_path = os.path.join(temp_dir, stored_name)

        photo.save(stored_path)
        logger.debug(f"Incoming picture saved to '{stored_path}'")

        def _do_app_uu_upload_photo(wowi: WowiPy, uu_id: int, media_path: str):
            wowi_file: MediaData
            rslt: wowipy.models.Result
            wowi_file = MediaData(
                file_name=os.path.basename(media_path),
                creation_date_str=datetime.now().strftime("%y-%m-%d"),
                entity_type_name="UseUnit",
                entity_id=uu_id
            )
            wowi_file.picture_type_name = "Sonstiges"
            uplresult: Result
            uplresult = wowi.upload_media(wowi_file, media_path)
            if uplresult.status_code not in [200,201]:
                logger.error(f"upload_media: Upload failed for use unit id '{uu_id}'. Message: {uplresult.message}")
            else:
                logger.info(f"upload_media: Uploaded photo to use unit '{uu_id}. Result: {uplresult.message}'")

        with_wowi_retry(_do_app_uu_upload_photo, uu_id=use_unit_id, media_path=stored_path)

        return jsonify({"status": "ok", "use_unit_id": use_unit_id, "filename": stored_name}), 201

    @app.route("/app/use-unit/contacts/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_contact(use_unit_id):
        def _do_app_uu_contact(wowi: WowiPy, uu_id: int):
            contracts = wowi.get_license_agreements(license_agreement_active_on=datetime.now(),
                                                    add_args={"useUnitId": uu_id},
                                                    add_contractors=True
                                                    )
            if not contracts:
                return abort(404)
            the_contract: LicenseAgreement
            the_contract = contracts[0]
            if the_contract.restriction_of_use.is_vacancy:
                return abort(404)
            if not the_contract.contractors:
                return abort(404)

            contact_items = []
            contractor_entry: wowipy.wowipy.Contractor
            for contractor_entry in the_contract.contractors:
                the_person = contractor_entry.person
                if the_person.is_natural_person:
                    np = the_person.natural_person
                    title = f"{np.title} " if np.title else ""
                    person_name = f"{title}{np.last_name}, {np.first_name}"
                    person_gender = np.gender.name
                    try:
                        if isinstance(np.birth_date, str):
                            person_birth_date = np.birth_date
                        elif isinstance(np.birth_date, datetime):
                            person_birth_date = np.birth_date.strftime("%Y-%m-%d")
                        else:
                            person_birth_date = None
                    except (TypeError, AttributeError):
                        person_birth_date = None
                else:
                    person_name = the_person.legal_person.long_name1
                    person_gender = None
                    person_birth_date = None

                try:
                    person_email = the_person.first_email_communication.content or None
                except AttributeError:
                    person_email = None
                try:
                    person_phone = the_person.first_landline_phone_communication.content or None
                except AttributeError:
                    person_phone = None
                try:
                    person_mobile = the_person.first_mobile_phone_communication.content or None
                except AttributeError:
                    person_mobile = None
                try:
                    person_role = contractor_entry.contractor_type.name
                except (ValueError, AttributeError):
                    person_role = None

                if person_email or person_phone or person_mobile:
                    contact_entry = {
                        "role": person_role,
                        "name": person_name,
                        "gender": person_gender,
                        "email": person_email,
                        "phone": person_phone,
                        "mobile": person_mobile,
                        "birth_date": person_birth_date
                    }
                    contact_items.append(contact_entry)
            if not contact_items:
                return abort(404)
            else:
                return {
                    "contact_items": contact_items
                }
        oretval = with_wowi_retry(_do_app_uu_contact, uu_id=use_unit_id)
        return oretval

    @app.route("/app/use-unit/floor_plan/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_floor_plan(use_unit_id):
        def _do_app_uu_floor_plan(wowi: WowiPy, uu_id: int):
            uumedia = wowi.get_media(entity_name="UseUnit", entity_id=uu_id)
            for entry in uumedia:
                if entry.picture_type_name == "Grundriss":
                    with tempfile.TemporaryDirectory() as tmpdir:
                        file_path = os.path.join(tmpdir, entry.file_name)
                        wowi.download_media("UseUnit", entry.file_guid, tmpdir, entry.file_name)
                        return send_file(file_path, download_name=entry.file_name)
            return abort(404)
        oretval = with_wowi_retry(_do_app_uu_floor_plan, uu_id=use_unit_id)
        return oretval

    @app.route("/app/use-unit/search", methods=["GET"])
    @jwt_required()
    def route_search():
        cache = WowiCache(current_app.config['INI_CONFIG'].get("Wowicache", "connection_uri"))

        param_fulltext = request.args.get("fulltext")
        param_radius = request.args.get("radius")  # meters
        param_lat = request.args.get("lat")
        param_lon = request.args.get("lon")
        param_limit = request.args.get("limit")
        only_terminated = get_bool_arg("only_terminated")
        only_vacant = get_bool_arg("only_vacant")
        try:
            limit = int(param_limit)
        except (ValueError, TypeError):
            limit = LIMIT_DEFAULT
        if limit > LIMIT_MAX:
            limit = LIMIT_MAX

        current_user_id = int(get_jwt_identity())
        user: User
        user = User.query.get(current_user_id)
        user.last_action = datetime.now()
        user.last_lat = param_lat
        user.last_lon = param_lon
        user.last_ip = request.environ['REMOTE_ADDR']
        db.session.commit()

        q = cache.session.query(Building)

        q = apply_fulltext(q, param_fulltext)
        if param_radius and param_lat and param_lon:
            radius_m = float(param_radius)
            lat = float(param_lat)
            lon = float(param_lon)

            building_ids = building_ids_from_radius(lat, lon, radius_m)

            if not building_ids:
                return jsonify({"items": []}), 200

            q = q.filter(Building.internal_id.in_(building_ids))
        buildings = (
            q.order_by(Building.street_complete)
            .limit(limit)
            .all()
        )
        retval = []
        building: Building
        for building in buildings:
            uu_info = []
            uus = cache.session.query(UseUnit).filter(UseUnit.building_id == building.internal_id).all()
            uu: UseUnit
            object_has_relevant_use_units = False
            for uu in uus:
                contract_info = {}
                contract: Contract
                for contract in uu.contracts:
                    if contract.status_name == "beendet":
                        continue
                    if only_vacant and not contract.is_vacancy:
                        continue
                    if only_terminated and contract.status_name != "gekündigt":
                        continue
                    if not contract.is_vacancy:
                        contractor: Contractor
                        contractor = contract.contractors[0]
                        person: Person
                        person = contractor.person
                        contract_info = {
                            "id_num": contract.id_num,
                            "contractor_name": f"{person.last_name}, {person.first_name}",
                            "start": contract.contract_start,
                            "end": contract.contract_end
                        }
                    else:
                        contract_info = {
                            "id_num": contract.id_num,
                            "contractor_name": "Leerstand",
                            "start": contract.contract_start,
                            "end": contract.contract_end
                        }
                    object_has_relevant_use_units = True
                    break
                if (only_vacant or only_terminated) and not contract_info:
                    continue
                uu_info.append({
                    "id_num": uu.id_num,
                    "id": uu.internal_id,
                    "location": uu.description_of_position,
                    "contract": contract_info
                })
                location: Geolocation
            location = db.session.query(Geolocation).filter(Geolocation.building_id == building.internal_id).first()
            if location:
                loc_lat = location.lat
                loc_lon = location.lon
                distance = haversine_distance_m(location.lat, location.lon, param_lat, param_lon)
                if distance:
                    distance = round(distance)
            else:
                distance = None
                loc_lat = None
                loc_lon = None
            if not object_has_relevant_use_units:
                continue
            retval.append({
                "id": building.internal_id,
                "id_num": building.id_num,
                "street_complete": building.street_complete,
                "postcode": building.postcode,
                "town": building.town,
                "use_units": uu_info,
                "lat": loc_lat,
                "lon": loc_lon,
                "distance": distance
            })
        return jsonify({
            "items": retval
        })

    @app.route("/admin/events")
    @admin_required
    def admin_events_list():
        cache = WowiCache(current_app.config['INI_CONFIG'].get("Wowicache", "connection_uri"))
        page = request.args.get("page", 1, type=int)
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        user_name = (request.args.get("user_name") or "").strip()
        use_unit_idnum = (request.args.get("use_unit_idnum") or "").strip()

        query = EventItem.query

        from datetime import datetime, timedelta, time

        def parse_date(value: str):
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except Exception as e:
                print(str(e))
                return None

        df = parse_date(date_from) if date_from else None
        dt = parse_date(date_to) if date_to else None

        if df:
            query = query.filter(EventItem.stamp >= datetime.combine(df, time.min))
        if dt:
            query = query.filter(EventItem.stamp < datetime.combine(dt + timedelta(days=1), time.min))

        if user_name:
            query = query.filter(EventItem.user_name.ilike(f"%{user_name}%"))

        query = query.order_by(EventItem.stamp.desc(), EventItem.id.desc())

        pagination = query.paginate(page=page, per_page=50, error_out=False)
        events = pagination.items

        fac_ids = {e.facility_catalog_id for e in events if e.facility_catalog_id}
        comp_ids = {e.component_catalog_id for e in events if e.component_catalog_id}

        sub_ids = set()
        for e in events:
            if e.sub_component_ids:
                for part in str(e.sub_component_ids).split(","):
                    part = part.strip()
                    if part.isdigit():
                        sub_ids.add(int(part))

        facility_map = (
            {f.id: f.display_name for f in FacilityCatalogItem.query.filter(FacilityCatalogItem.id.in_(fac_ids)).all()}
            if fac_ids
            else {}
        )
        component_map = (
            {c.id: c.display_name for c in
             ComponentCatalogItem.query.filter(ComponentCatalogItem.id.in_(comp_ids)).all()}
            if comp_ids
            else {}
        )
        under_component_map = (
            {u.id: u.display_name for u in UnderComponentItem.query.filter(UnderComponentItem.id.in_(sub_ids)).all()}
            if sub_ids
            else {}
        )

        rows = []
        for e in events:
            sc_names = []
            if e.sub_component_ids:
                for part in str(e.sub_component_ids).split(","):
                    part = part.strip()
                    if part.isdigit():
                        sc_names.append(under_component_map.get(int(part), part))
                    elif part:
                        sc_names.append(part)
            use_unit: UseUnit
            use_unit = cache.session.query(UseUnit).filter(UseUnit.internal_id == e.use_unit_id).first()
            uu_idnum: str | None
            if use_unit:
                uu_idnum = use_unit.id_num
                if use_unit_idnum:
                    if not uu_idnum.startswith(use_unit_idnum):
                        continue
            else:
                uu_idnum = None

            rows.append(
                {
                    "stamp": e.stamp,
                    "user_name": e.user_name,
                    "action": e.action,
                    "use_unit_idnum": uu_idnum,
                    "component_name": component_map.get(e.component_catalog_id) if e.component_catalog_id else None,
                    "facility_name": facility_map.get(e.facility_catalog_id) if e.facility_catalog_id else None,
                    "sub_component_names": ", ".join(sc_names) if sc_names else None,
                }
            )

        return render_template(
            "admin/events_list.html",
            rows=rows,
            pagination=pagination,
            date_from=date_from,
            date_to=date_to,
            user_name=user_name,
            use_unit_idnum=use_unit_idnum,
        )

    @app.route("/admin/highscore")
    @admin_required
    def admin_highscore():
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()

        def parse_date(value: str):
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except Exception as ex:
                print(str(ex))
                return None

        df = parse_date(date_from) if date_from else None
        dt = parse_date(date_to) if date_to else None

        query = EventItem.query.filter(EventItem.action.in_(["create", "edit"]))

        if df:
            query = query.filter(EventItem.stamp >= datetime.combine(df, time.min))
        if dt:
            query = query.filter(EventItem.stamp < datetime.combine(dt + timedelta(days=1), time.min))

        query = query.order_by(EventItem.user_name.asc(), EventItem.use_unit_id.asc(), EventItem.stamp.asc(),
                               EventItem.id.asc())

        cooldown = timedelta(days=7)

        points_by_user = {}
        last_scored = {}

        for e in query.yield_per(2000):
            if not e.user_name:
                continue
            if not e.use_unit_id:
                continue

            user_key = e.user_name
            unit_key = e.use_unit_id
            t = e.stamp

            if t is None:
                continue

            user_units = last_scored.get(user_key)
            if user_units is None:
                user_units = {}
                last_scored[user_key] = user_units

            last_time = user_units.get(unit_key)
            if last_time is None or t >= last_time + cooldown:
                points_by_user[user_key] = points_by_user.get(user_key, 0) + 1
                user_units[unit_key] = t

        top = sorted(points_by_user.items(), key=lambda x: (-x[1], x[0]))[:10]
        rows = [{"rank": i + 1, "user_name": u, "points": p} for i, (u, p) in enumerate(top)]

        return render_template(
            "admin/highscore.html",
            rows=rows,
            date_from=date_from,
            date_to=date_to,
        )
