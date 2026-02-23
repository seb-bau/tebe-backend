from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from wowipy.wowipy import WowiPy, ComponentElement
from app.models import User, Role, FacilityCatalogItem, ComponentCatalogItem, RawPayload
from app.models import FacilityItem
from app.extensions import db
from flask import current_app
from app.erp import with_wowi_retry
import logging
from app.helpers import _json_from_file

logger = logging.getLogger()


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

        role_id = user.role_id

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
                if not fac_item:
                    logger.error(f"app_uu_current_data: No facility found for component '{component.id_}', "
                                 f"facility id '{component.facility_id}'")
                    continue
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

            comp_cat = db.session.query(ComponentCatalogItem).filter(
                ComponentCatalogItem.enabled.is_(True),
                ComponentCatalogItem.roles.any(Role.id == role_id),
            ).all()

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

    from app.celery_app import celery

    @app.route("/app/use-unit/data/write/<int:use_unit_id>", methods=["POST"])
    @jwt_required()
    def app_uu_write_data(use_unit_id):
        if current_app.config["DEMO_MODE"]:
            return jsonify({"msg": "ok"}), 200

        data = request.get_json(silent=True)
        if not isinstance(data, list):
            return jsonify({"msg": "invalid payload"}), 400

        if current_app.config["STORE_PAYLOADS"]:
            new_payload = RawPayload(payload=data)
            db.session.add(new_payload)
            db.session.commit()

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
