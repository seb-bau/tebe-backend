from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import User, GeoBuilding, ErpUseUnit
from app.extensions import db
from flask import current_app
from sqlalchemy import or_, inspect, func
from app.geo import get_buildings_in_radius_m, haversine_distance_m
from datetime import datetime
import logging
import numbers
import re
from app.helpers import _json_from_file

LIMIT_MAX = 50
LIMIT_DEFAULT = 50

SCOPE_TENANT = "tenant"
SCOPE_ADDRESS = "address"

logger = logging.getLogger()


def tokenize_fulltext(fulltext: str):
    ft = (fulltext or "").strip()
    if not ft:
        return []
    return [t.strip() for t in re.split(r"[\s,;]+", ft) if t.strip()]


def build_tenant_query(query, fulltext: str):
    tokens = tokenize_fulltext(fulltext)

    if not tokens:
        return query

    full_name_1 = (
        func.coalesce(ErpUseUnit.contractor_first_name_1, "") + " " +
        func.coalesce(ErpUseUnit.contractor_last_name_1, "")
    )
    full_name_2 = (
        func.coalesce(ErpUseUnit.contractor_last_name_1, "") + " " +
        func.coalesce(ErpUseUnit.contractor_first_name_1, "")
    )

    for token in tokens:
        like = f"%{token}%"
        query = query.filter(or_(
            ErpUseUnit.contractor_last_name_1.ilike(like),
            ErpUseUnit.contractor_first_name_1.ilike(like),
            ErpUseUnit.contractor_last_name_2.ilike(like),
            ErpUseUnit.contractor_first_name_2.ilike(like),
            full_name_1.ilike(like),
            full_name_2.ilike(like),
        ))

    return query


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


def register_routes_api_masterdata(app):
    def buildings_from_radius(lat, lon, radius_m, limit=None):
        locations_found = get_buildings_in_radius_m(lat, lon, radius_m=radius_m)
        locations_found = sorted(locations_found, key=lambda x: x["distance_m"])
        if limit is not None:
            locations_found = locations_found[:limit]
        return locations_found

    def apply_fulltext(query, fulltext: str, search_scope: str):
        tokens = tokenize_fulltext(fulltext)
        if not tokens:
            return query

        for token in tokens:
            like = f"%{token}%"

            geo_filter = or_(
                GeoBuilding.street.ilike(like),
                GeoBuilding.street_complete.ilike(like),
                GeoBuilding.postcode.ilike(like),
                GeoBuilding.town.ilike(like),
                GeoBuilding.erp_idnum.ilike(like),
            )

            tenant_exists = (
                build_tenant_query(
                    db.session.query(ErpUseUnit.id)
                    .filter(ErpUseUnit.erp_building_id == GeoBuilding.erp_id),
                    token
                ).exists()
            )

            if search_scope == SCOPE_TENANT:
                query = query.filter(tenant_exists)
            elif search_scope == SCOPE_ADDRESS:
                query = query.filter(geo_filter)
            else:
                query = query.filter(or_(geo_filter, tenant_exists))

        return query

    @app.route("/app/use-unit/search", methods=["GET"])
    @jwt_required()
    def route_search():
        if current_app.config["DEMO_MODE"]:
            return _json_from_file(current_app.config["DEMO_SEARCH"])

        param_fulltext = request.args.get("fulltext")
        param_radius = request.args.get("radius")
        param_lat = request.args.get("lat")
        param_lon = request.args.get("lon")
        param_limit = request.args.get("limit")
        only_terminated = get_bool_arg("only_terminated")
        only_vacant = get_bool_arg("only_vacant")

        if param_fulltext:
            # Ignore radius if fulltext search is active
            param_radius = None

        lat = None
        lon = None
        distance_map = {}

        try:
            limit = int(param_limit)
        except (ValueError, TypeError):
            limit = LIMIT_DEFAULT

        if limit > LIMIT_MAX:
            limit = LIMIT_MAX

        current_user_id = int(get_jwt_identity())
        user: User = User.query.get(current_user_id)
        user.last_action = datetime.now()
        user.last_lat = param_lat
        user.last_lon = param_lon
        user.last_ip = request.environ["REMOTE_ADDR"]
        db.session.commit()

        q = db.session.query(GeoBuilding)
        search_scope = request.args.get("search_scope") or SCOPE_ADDRESS
        q = apply_fulltext(q, param_fulltext, search_scope)

        if param_radius and param_lat and param_lon:
            radius_m = float(param_radius)
            lat = float(param_lat)
            lon = float(param_lon)

            nearby_buildings = buildings_from_radius(lat, lon, radius_m, limit=limit)
            building_ids = [item["building_id"] for item in nearby_buildings if item.get("building_id")]
            distance_map = {
                item["building_id"]: item["distance_m"]
                for item in nearby_buildings
                if item.get("building_id")
            }

            if not building_ids:
                return jsonify({"items": []}), 200

            q = q.filter(GeoBuilding.erp_id.in_(building_ids))
            buildings = q.all()

            building_map = {b.erp_id: b for b in buildings}
            buildings = [building_map[building_id] for building_id in building_ids if building_id in building_map]
        else:
            buildings = (
                q.order_by(GeoBuilding.street_complete)
                .limit(limit)
                .all()
            )

        retval = []

        building: GeoBuilding
        for building in buildings:
            uu_info = []

            uu_query = db.session.query(ErpUseUnit).filter(
                ErpUseUnit.erp_building_id == building.erp_id
            )

            if param_fulltext and search_scope == SCOPE_TENANT:
                uu_query = build_tenant_query(uu_query, param_fulltext)

            uus = uu_query.all()

            object_has_relevant_use_units = False

            uu: ErpUseUnit
            for uu in uus:
                if only_vacant and not uu.is_vacancy:
                    continue
                if only_terminated and not uu.is_cancelled:
                    continue

                if not uu.is_vacancy:
                    contract_info = {
                        "id_num": uu.erp_contract_idnum,
                        "contractor_name": f"{uu.contractor_last_name_1}, {uu.contractor_first_name_1}",
                        "start": uu.contract_start,
                        "end": uu.contract_end
                    }
                else:
                    contract_info = {
                        "id_num": uu.erp_contract_idnum,
                        "contractor_name": "Leerstand",
                        "start": uu.contract_start,
                        "end": uu.contract_end
                    }

                if (only_vacant or only_terminated) and not contract_info:
                    continue

                object_has_relevant_use_units = True

                uu_info.append({
                    "id_num": uu.erp_idnum,
                    "id": uu.erp_id,
                    "location": uu.description_of_position,
                    "contract": contract_info
                })

            if not object_has_relevant_use_units:
                continue

            loc_lat = building.lat
            loc_lon = building.lon

            if building.erp_id in distance_map:
                distance = round(distance_map[building.erp_id])
            elif lat is not None and lon is not None:
                distance = round(haversine_distance_m(loc_lat, loc_lon, lat, lon))
            else:
                distance = None

            retval.append({
                "id": building.erp_id,
                "id_num": building.erp_idnum,
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
