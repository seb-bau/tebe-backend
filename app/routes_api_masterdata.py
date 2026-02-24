from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import User, GeoBuilding
from app.extensions import db
from flask import current_app
from sqlalchemy import or_, inspect
from app.geo import get_buildings_in_radius_m, haversine_distance_m
from wowicache.models import WowiCache, Building, UseUnit, Contract, Contractor, Person
from datetime import datetime
import logging
import numbers
from app.helpers import _json_from_file

LIMIT_MAX = 20
LIMIT_DEFAULT = 20

logger = logging.getLogger()


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
        if current_app.config['DEMO_MODE']:
            return _json_from_file(current_app.config['DEMO_SEARCH'])

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
                location: GeoBuilding
            location = db.session.query(GeoBuilding).filter(GeoBuilding.erp_id == building.internal_id).first()
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
