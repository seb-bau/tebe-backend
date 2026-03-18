from flask import request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from wowipy.wowipy import WowiPy
from wowipy.models import UseUnit, MediaData

from app.helpers import normalize_exif_orientation
from app.models import User, ResponsibleOfficial
from flask import current_app, send_file
from app.erp import with_wowi_retry, download_floor_plan, get_wowi_client, download_photo
from app.extensions import db
from app.payloads import store_payload
import logging
import base64
import mimetypes

logger = logging.getLogger()


def register_routes_api_media(app):
    from app.celery_app import celery
    from werkzeug.utils import secure_filename
    import os
    import tempfile
    import uuid

    @app.route("/app/use-unit/photos", methods=["POST"])
    @jwt_required()
    def route_use_unit_photos():
        if current_app.config["DEMO_MODE"]:
            return jsonify({"msg": "ok"}), 201

        store_payload()

        photo = request.files.get("photo")
        use_unit_id_raw = request.form.get("use_unit_id")
        description = request.form.get("description")
        current_user_id = int(get_jwt_identity())
        ip_address = request.environ.get("REMOTE_ADDR")
        user = User.query.get(current_user_id)
        last_lat = getattr(user, "last_lat", None) if user else None
        last_lon = getattr(user, "last_lon", None) if user else None
        try:
            picture_type = int(request.form.get("picture_type"))
            media_entity = int(request.form.get("media_entity"))
        except ValueError as e:
            logger.error(f"route_use_unit_photos: User '{user.name}' tried to upload photo to uu "
                         f"'{str(use_unit_id_raw)}' with error '{str(e)}'")
            return jsonify({"status": "error", "message": "Incorrect values for picture_type or media_entity"}), 400

        if photo is None or not photo.filename:
            logger.error(f"route_use_unit_photos: User '{user.name}' tried to upload photo to uu "
                         f"'{str(use_unit_id_raw)}' with error: Missing photo")
            return jsonify({"status": "error", "message": "Missing photo"}), 400

        try:
            use_unit_id = int(use_unit_id_raw)
        except (TypeError, ValueError):
            logger.error(f"route_use_unit_photos: User '{user.name}' tried to upload photo to uu "
                         f"'{str(use_unit_id_raw)}' with error: Invalid use unit id")
            return jsonify({"status": "error", "message": "Invalid use_unit_id"}), 400

        temp_dir = os.path.join(tempfile.gettempdir(), "tebe_use_unit_photos")
        os.makedirs(temp_dir, exist_ok=True)

        original_name = secure_filename(photo.filename) or "photo"
        stored_name = f"{use_unit_id}_{uuid.uuid4().hex}_{original_name}"
        stored_path = os.path.join(temp_dir, stored_name)

        photo.save(stored_path)

        celery.send_task("tasks.upload_erp_photo", args=[use_unit_id,
                                                         stored_path,
                                                         picture_type,
                                                         media_entity,
                                                         description,
                                                         current_user_id,
                                                         ip_address,
                                                         last_lat,
                                                         last_lon])

        return jsonify({"status": "ok", "use_unit_id": use_unit_id, "filename": stored_name}), 201

    @app.route("/app/use-unit/floor_plan/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_floor_plan(use_unit_id):
        if current_app.config['DEMO_MODE']:
            return send_file(current_app.config['DEMO_FLOOR_PLAN'], download_name="demo_plan.png")

        def _do_app_uu_floor_plan(wowi: WowiPy, uu_id: int):
            floor_plan_file = download_floor_plan(wowi, uu_id)
            if not floor_plan_file:
                return abort(404)
            return send_file(floor_plan_file["file_path"], download_name=floor_plan_file["file_name"])

        oretval = with_wowi_retry(_do_app_uu_floor_plan, uu_id=use_unit_id)
        return oretval

    @app.route("/app/floor_plan_catalog", methods=["GET"])
    @jwt_required()
    def app_floor_plan_catalog():
        if current_app.config['DEMO_MODE']:
            return abort(404)

        floor_plan_official = current_app.config['INI_CONFIG'].get("OpenWowi", "floor_plan_official", fallback=None)
        plan_change_subject = current_app.config['INI_CONFIG'].get("OpenWowi", "floor_plan_subject", fallback=None)
        plan_change_content = current_app.config['INI_CONFIG'].get("OpenWowi", "floor_plan_content", fallback=None)
        if not floor_plan_official:
            return abort(404)
        official = (db.session.query(ResponsibleOfficial)
                    .filter(ResponsibleOfficial.erp_user_id == floor_plan_official)
                    .first()
                    )
        if not official:
            return abort(404)

        return jsonify({
            "plan_official_erp_id": floor_plan_official,
            "plan_change_subject": plan_change_subject,
            "plan_change_content": plan_change_content
        })

    @app.route("/app/use-unit/<int:use_unit_id>/photos", methods=["GET"])
    @jwt_required()
    def route_use_unit_photos_get(use_unit_id):
        def handle_media_entries(media_entries: list, entity_name: str) -> list:
            retmed = []
            if not media_entries:
                return []
            media_entry: MediaData
            for media_entry in media_entries:
                temp_dir = os.path.join(tempfile.gettempdir(), "tebe_photos")
                os.makedirs(temp_dir, exist_ok=True)
                dest_file_name = f"{uuid.uuid4().hex}_{media_entry.thumb_name}"
                full_dest_path = os.path.join(temp_dir, dest_file_name)
                wowi.download_media(entity_name=entity_name,
                                    file_guid=media_entry.thumb_guid,
                                    dest_file_path=temp_dir,
                                    dest_file_name=dest_file_name,
                                    is_thumbnail=True)

                normalize_exif_orientation(full_dest_path)

                with open(full_dest_path, "rb") as f:
                    encoded = base64.b64encode(f.read()).decode("utf-8")
                mime_type, _ = mimetypes.guess_type(full_dest_path)

                retmed.append({
                    "id": media_entry.id_,
                    "thumb_guid": media_entry.thumb_guid,
                    "file_guid": media_entry.file_guid,
                    "description": media_entry.remark,
                    "date": media_entry.creation_date,
                    "entity": entity_name,
                    "thumb_base64":  encoded,
                    "thumb_mime_type": mime_type or "application/octet-stream",
                })
            return retmed

        fallback_return = jsonify({
            "media_items": []
        })
        if current_app.config["DEMO_MODE"]:
            return fallback_return, 200

        wowi = get_wowi_client()
        error_string = None
        try:
            uu_objects = wowi.get_use_units(use_unit_id=use_unit_id)
        except Exception as e:
            error_string = str(e)
            uu_objects = None

        if not uu_objects:
            logger.error(f"use_unit_photos_get: Could not get use unit from wowipy: {error_string}")
            return fallback_return
        uu_object: UseUnit
        uu_object = uu_objects[0]
        building_id = uu_object.building_land.id_

        media_for_uu = wowi.get_media(entity_name="UseUnit", entity_id=use_unit_id)
        media_for_building = wowi.get_media(entity_name="Building", entity_id=building_id)
        lst_uu = handle_media_entries(media_for_uu, "UseUnit")
        lst_bld = handle_media_entries(media_for_building, "Building")
        retlst = lst_uu + lst_bld
        return jsonify(
            {
                "media_items": retlst
            }
        )

    @app.route("/app/photo/<entity_name>/<int:media_id>", methods=["GET"])
    @jwt_required()
    def app_photo_get(entity_name, media_id):
        if current_app.config['DEMO_MODE']:
            return abort(404)

        def _do_app_photo_get(wowi: WowiPy, ent_name: str, m_id: int):
            photo_file = download_photo(wowi, ent_name, m_id)
            if not photo_file:
                return abort(404)
            return send_file(photo_file["file_path"], download_name=photo_file["file_name"])

        oretval = with_wowi_retry(_do_app_photo_get, entity_name, media_id)
        return oretval
