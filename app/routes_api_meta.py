from flask import jsonify
from flask_jwt_extended import jwt_required
from app.models import MediaEntity, EstatePictureType
from app.extensions import db
from flask import current_app
import logging

logger = logging.getLogger()


def register_routes_api_meta(app):
    @app.route("/app/media_catalog", methods=["GET"])
    @jwt_required()
    def route_media_catalog():
        if current_app.config["DEMO_MODE"]:
            return jsonify({"msg": "ok"}), 201

        picture_types = []
        media_entities = []

        all_types = db.session.query(EstatePictureType).all()
        for entry in all_types:
            new_retval = {
                "id": entry.id,
                "name": entry.name,
                "code": entry.code
            }
            picture_types.append(new_retval)

        all_entites = db.session.query(MediaEntity).all()
        for entry in all_entites:
            new_retval = {
                "id": entry.id,
                "name": entry.name
            }
            media_entities.append(new_retval)

        complete_ret = {
            "picture_types": picture_types,
            "media_entities": media_entities
        }
        return jsonify(complete_ret)
