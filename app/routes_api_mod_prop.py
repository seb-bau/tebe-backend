import os
import uuid
import json
from pathlib import Path

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from app.models import ModPropMeasure, ErpUseUnit, User
from flask import current_app
import logging
from app.extensions import db
from app.payloads import store_payload

logger = logging.getLogger()

MAX_FILES = 20
ALLOWED_EXT = {".jpg", ".jpeg", ".png"}
CONTEXT_BUILDING = "building"
CONTEXT_ECO_UNIT = "eco_unit"
CONTEXT_BUILDING_GROUP = "building_group"


def allowed_filename(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXT


def normalize_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def register_routes_api_mod_prop(app):
    @app.route("/app/modprop/measures", methods=["GET"])
    @jwt_required()
    def route_api_modprop_measures():
        retval = []
        measures = db.session.query(ModPropMeasure).order_by(ModPropMeasure.name).all()
        for measure in measures:
            retval.append({
                "id": measure.id,
                "name": measure.name
            })
        return jsonify(retval)

    @app.route("/app/modprop/create", methods=["POST"])
    @jwt_required()
    def route_api_modprop_create():
        store_payload()
        use_unit_id = int(request.form.get("use_unit_id"))
        use_unit_obj: ErpUseUnit
        use_unit_obj = db.session.query(ErpUseUnit).filter(ErpUseUnit.erp_id == use_unit_id).first()
        measure_id = int(request.form.get("measure_id"))
        measure_obj = db.session.get(ModPropMeasure, measure_id)
        context_raw = request.form.get("context")
        description = request.form.get("description")
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)

        context_description = ""
        if context_raw == CONTEXT_ECO_UNIT:
            context_description = "(Dieser Vorschlag gilt für die gesamte Wirtschaftseinheit)\n"
        elif context_raw == CONTEXT_BUILDING_GROUP:
            context_description = "(Dieser Vorschlag gilt für die gesamte Gebäudegruppe)\n"

        description = f"{context_description}{description}"

        dest_dir = current_app.config["INI_CONFIG"].get("ModProp", "dest_dir", fallback="/tmp/modprop")
        dest_dir_json = os.path.join(dest_dir, "in")
        dest_dir_photos = os.path.join(dest_dir, "photos")
        os.makedirs(dest_dir_json, exist_ok=True)
        os.makedirs(dest_dir_photos, exist_ok=True)

        files = request.files.getlist("photos[]")
        saved = []
        for f in files:
            if not f or not f.filename:
                continue

            original = secure_filename(f.filename)
            if not allowed_filename(original):
                return jsonify({"error": f"invalid file type: {original}"}), 400

            ext = Path(original).suffix.lower()
            stored_name = f"{uuid.uuid4().hex}{ext}"
            path = os.path.join(dest_dir_photos, stored_name)

            f.save(path)
            saved.append(stored_name)

        dest_json = {
            "measure_id": measure_obj.erp_id,
            "user": user.email.lower(),
            "description": description,
            "building_id": use_unit_obj.erp_building_id,
            "photos": saved
        }
        json_filename = f"{uuid.uuid4().hex}.json"
        json_path = os.path.join(dest_dir_json, json_filename)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(dest_json, f, ensure_ascii=False, indent=4)

        return jsonify({"msg": "created"}), 201
