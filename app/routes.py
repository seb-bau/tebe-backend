from flask import render_template, request, jsonify, flash, abort, redirect, url_for
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from app.erp import create_facility, create_component, edit_component
from wowipy.wowipy import WowiPy
from app.models import User, TokenBlocklist, FacilityCatalogItem, ComponentCatalogItem, UnderComponentItem, Geolocation
from app.extensions import db
from flask import current_app
from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps
from sqlalchemy import or_
from app.erp import with_wowi_retry
from app.geo import get_buildings_in_radius_m, haversine_distance_m
from wowicache.models import WowiCache, Building, UseUnit, Contract, Contractor, Person
import logging
import numbers


logger = logging.getLogger('root')


def is_numeric(value):
    return isinstance(value, numbers.Number)


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
            enabled = bool(request.form.get("enabled"))
            custom_name = request.form.get("custom_name") or None

            facility.enabled = enabled
            facility.custom_name = custom_name

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
                        under_components.append({
                            "id": uc.id,
                            "name": uc.name,
                            "selected": any(c.id_ == uc.id for c in component.under_components)
                        })
                else:
                    under_components = None
                retval_existing.append({
                    "id": component.id_,
                    "name": component.name,
                    "component_catalog_id": component.component_catalog_id,
                    "quantitiy": component.count,
                    "unit": comp_cat_item.quantity_type_name,
                    "under_components": under_components,
                    "facility_cat_id": component.facility_id,
                    "is_bool": comp_cat_item.is_bool,
                    "single_under_component": comp_cat_item.single_under_component,
                    "hide_quantity": comp_cat_item.hide_quantity
                })
                found_types.append(comp_cat_item.id)

            comp_cat = db.session.query(ComponentCatalogItem).filter(ComponentCatalogItem.enabled.is_(True)).all()
            cat_item: ComponentCatalogItem
            for cat_item in comp_cat:
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

                psub = entry.get("sub_components") or []
                if not entry.get("component_id"):
                    if entry.get("is_unknown"):
                        # Wenn es die Komponente noch nicht gab und sie unbekannt istm können wir sie direkt
                        # ignorieren
                        print("ignore")
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
                    component_id = create_component(wowi,
                                                    component_catalog_id=comp_cat_item.id,
                                                    facility_id=uu_facility,
                                                    count=int(entry.get("quantity")),
                                                    psub_components=psub
                                                    )
                    components_created += 1
                    if not component_id:
                        return abort(500, "Error while creating component")
                    logger.info(f"app_uu_write_data: Created component {component_id}")
                else:
                    unknown = bool(entry.get("is_unknown"))
                    edit_component(wowi, entry.get("component_id"), int(entry.get("quantity")), psub_components=psub,
                                   unknown=unknown)
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

    @app.route("/app/use-unit/search", methods=["GET"])
    @jwt_required()
    def route_search():
        cache = WowiCache(current_app.config['INI_CONFIG'].get("Wowicache", "connection_uri"))

        param_fulltext = request.args.get("fulltext")
        param_radius = request.args.get("radius")  # meters
        param_lat = request.args.get("lat")
        param_lon = request.args.get("lon")

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

        buildings = q.order_by(Building.street_complete).all()

        retval = []
        building: Building
        for building in buildings:
            uu_info = []
            uus = cache.session.query(UseUnit).filter(UseUnit.building_id == building.internal_id).all()
            uu: UseUnit
            for uu in uus:
                contract_info = {}
                contract: Contract
                for contract in uu.contracts:
                    if contract.status_name == "aktiv":
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
                    break
                uu_info.append({
                    "id_num": uu.id_num,
                    "id": uu.internal_id,
                    "location": uu.description_of_position,
                    "contract": contract_info
                })
                location: Geolocation
            location = db.session.query(Geolocation).filter(Geolocation.building_id == building.internal_id).first()
            if location:
                distance = round(haversine_distance_m(location.lat, location.lon, param_lat, param_lon))
            else:
                distance = None
            retval.append({
                "id": building.internal_id,
                "id_num": building.id_num,
                "street_complete": building.street_complete,
                "postcode": building.postcode,
                "town": building.town,
                "use_units": uu_info,
                "lat": location.lat,
                "lon": location.lon,
                "distance": distance
            })
        return jsonify({
            "items": retval
        })
