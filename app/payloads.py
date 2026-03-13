from flask import request
from flask import current_app
from app.models import RawPayload
from flask_jwt_extended import get_jwt_identity
from app.extensions import db
import logging


logger = logging.getLogger()


def store_payload():
    if not current_app.config["STORE_PAYLOADS"]:
        return

    data = request.get_json(silent=True)

    if data is None:
        if request.form:
            data = request.form.to_dict(flat=False)

    current_user_id = int(get_jwt_identity())

    new_payload = RawPayload(
        payload=data,
        route=request.url,
        method=request.method,
        user_id=current_user_id
    )

    db.session.add(new_payload)
    db.session.commit()
