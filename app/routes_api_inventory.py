from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from wowipy.wowipy import WowiPy, ComponentElement
from app.models import User, Role, FacilityCatalogItem, ComponentCatalogItem
from app.models import FacilityItem
from app.extensions import db
from flask import current_app
from app.erp import with_wowi_retry
import logging
from app.helpers import _json_from_file
from app.payloads import store_payload
from datetime import datetime

logger = logging.getLogger()


def component_valid(comp_object: ComponentElement) -> bool:
    # Hinweis: Wir behandeln keine Komponenten, die evtl. in die Zukunft eingetragen wurden.
    # Fallback der Methode ist "True", weil das valid_to-Feld eher selten im ERP genutzt wird.
    if not comp_object.valid_to:
        return True

    check_date = None
    if isinstance(comp_object.valid_to, datetime):
        check_date = comp_object.valid_to
    elif isinstance(comp_object.valid_to, str):
        try:
            check_date = datetime.strptime(comp_object.valid_to, "%Y-%m-%d")
        except ValueError as e:
            logger.error(f"component_valid: ValueError while converting valid_to to datetime."
                         f"Comp-ID: {comp_object.id_}, "
                         f"valid_to: {comp_object.valid_to}, "
                         f"ValueError: {str(e)}")
            return True

    if not check_date:
        logger.error(f"component_valid: valid_to-Date is neither datetime nor str."
                     f"Comp-ID: {comp_object.id_}, "
                     f"valid_to: {comp_object.valid_to}, "
                     f"Type: {type(comp_object.valid_to)}")
        return True

    if check_date >= datetime.now():
        return True

    return False


def component_valid_selection(comp_object: ComponentElement, cat_item: ComponentCatalogItem) -> bool:
    if not cat_item.single_under_component:
        return True
    if not comp_object.under_components:
        return False
    if len(comp_object.under_components) != 1:
        return False
    return True


def correct_quantity(under_component_list: list | None, current_quantitiy: int, component_id: int) -> int:
    # It is possible, that the User issued the negative UnderComponent for the component but set the
    # quantitiy to 1. This signals an inconsistent state to the app
    # Workaround: If Undercomponent is set to "No" set quantity to 0
    if not under_component_list:
        return current_quantitiy
    bool_handling = current_app.config["INI_CONFIG"].get("Handling", "bool_handling", fallback="quantity")
    if bool_handling.lower() != "sub_components":
        return current_quantitiy
    sub_component_yes_id = current_app.config["INI_CONFIG"].getint(
        "Handling", "bool_sub_component_yes_id", fallback=0)
    sub_component_no_id = current_app.config["INI_CONFIG"].getint(
        "Handling", "bool_sub_component_no_id", fallback=0)
    if not sub_component_yes_id or not sub_component_no_id:
        return current_quantitiy

    if any(c["id"] == sub_component_yes_id and c["selected"] for c in under_component_list) and current_quantitiy < 1:
        logger.warning(f"correct_quantity: Incorrect quantity for component id {component_id}. Yes-UnderComp selected"
                       f" but quantity < 1")
        return 1

    if any(c["id"] == sub_component_no_id and c["selected"] for c in under_component_list) and current_quantitiy > 0:
        logger.warning(f"correct_quantity: Incorrect quantity for component id {component_id}. No-UnderComp selected"
                       f" but quantity > 0")
        return 0
    return current_quantitiy


def register_routes_api_inventory(app):
    @app.route("/app/use-unit/data/current/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_current_data(use_unit_id):
        if current_app.config['DEMO_MODE']:
            return _json_from_file(current_app.config['DEMO_CUR_DATA'])
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if not user or not user.role_id:
            return jsonify({"msg": "user has no role"}), 403

        # Erlaubte Komponenten sind erlaubt und für die entsprechende Benutzerrolle aktiv
        role_id = user.role_id
        allowed_components = db.session.query(ComponentCatalogItem).filter(
            ComponentCatalogItem.enabled.is_(True),
            ComponentCatalogItem.roles.any(Role.id == role_id),
        ).all()

        allowed_component_ids = {item.id for item in allowed_components}

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
                if component.component_catalog_id not in allowed_component_ids:
                    continue

                if not component_valid(component):
                    continue

                if not component_valid_selection(component, comp_cat_item):
                    delete_option = current_app.config["INI_CONFIG"].getboolean(
                        "Handling", "del_comp_without_selection",
                        fallback=False)
                    if delete_option:
                        try:
                            wowi.delete_component(component.facility_id, component.id_)
                            logger.warning(f"uu_current_data: Deleted component {component.id_} because of incorrect "
                                           f"selection.")
                        except Exception as e:
                            logger.error(f"uu_current_data: Should delete comp {component.id_} but error occured: "
                                         f"{str(e)}")
                    else:
                        logger.warning(f"uu_current_data: Ignored component {component.id_} because of incorrect "
                                       f"selection. Config Item: {delete_option}")
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
                if not fac_item:
                    logger.error(f"app_uu_current_data: No facility found for component '{component.id_}', "
                                 f"facility id '{component.facility_id}'")
                    continue
                fac_cat = db.session.get(FacilityCatalogItem, fac_item.facility_catalog_item_id)
                retval_existing.append({
                    "id": component.id_,
                    "name": comp_cat_item.name,
                    "component_catalog_id": component.component_catalog_id,
                    "quantitiy": correct_quantity(under_components, int(component.count), component.id_),
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

            cat_item: ComponentCatalogItem
            for cat_item in allowed_components:
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

    from app.celery_app import celery

    @app.route("/app/use-unit/data/write/<int:use_unit_id>", methods=["POST"])
    @jwt_required()
    def app_uu_write_data(use_unit_id):
        if current_app.config["DEMO_MODE"]:
            return jsonify({"msg": "ok"}), 200

        store_payload()

        data = request.get_json(silent=True)
        if not isinstance(data, list):
            return jsonify({"msg": "invalid payload"}), 400

        current_user_id = int(get_jwt_identity())
        ip_address = request.environ.get("REMOTE_ADDR")
        user = User.query.get(current_user_id)
        last_lat = getattr(user, "last_lat", None) if user else None
        last_lon = getattr(user, "last_lon", None) if user else None

        celery.send_task(
            "tasks.write_use_unit_data",
            args=[use_unit_id, data, current_user_id, ip_address, last_lat, last_lon],
        )

        return jsonify({"status": "queued"}), 200
