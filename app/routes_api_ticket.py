import tempfile
import os
import uuid
from pathlib import Path

from flask import request, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

from app.erp import get_responsible_official, get_wowi_client
from wowipy.wowipy import WowiPy
import wowipy.models
from app.models import ResponsibleOfficial, Department, CheckList, CheckListItem, User, EstatePictureType, MediaEntity
from flask import current_app
import logging
from app.extensions import db

logger = logging.getLogger()

MAX_FILES = 5
ALLOWED_EXT = {".jpg", ".jpeg", ".png"}


def allowed_filename(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXT


def normalize_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def register_routes_api_ticket(app):
    from app.celery_app import celery

    @app.route("/app/ticket/create", methods=["POST"])
    @jwt_required()
    def route_api_ticket_create():
        wowi = get_wowi_client()
        use_unit_id = normalize_int(request.form.get("use_unit_id"))
        department_id = normalize_int(request.form.get("dest_department_id"))
        dest_user_id = normalize_int(request.form.get("dest_user_id"))
        is_floor_plan_change = bool(request.form.get("is_floor_plan_change"))
        temp_dir = os.path.join(tempfile.gettempdir(), "tebe_ticket_photos")
        os.makedirs(temp_dir, exist_ok=True)
        subject = request.form.get("subject")
        content = request.form.get("content")
        upload_floor_plan = current_app.config["INI_CONFIG"].get("OpenWowi", "replace_floor_plan", fallback=False)

        current_user_id = int(get_jwt_identity())
        ip_address = request.environ.get("REMOTE_ADDR")
        user = User.query.get(current_user_id)
        last_lat = getattr(user, "last_lat", None) if user else None
        last_lon = getattr(user, "last_lon", None) if user else None

        if not department_id and not dest_user_id:
            return jsonify({"msg": "missing arguments"}), 400
        if not use_unit_id or not subject or not content:
            return jsonify({"msg": "missing arguments"}), 400

        if department_id and dest_user_id:
            # Wenn beides angegeben wurde, gewinnt der Benutzereintrag
            department_id = None

        if department_id:
            resp: ResponsibleOfficial
            resp = get_responsible_official(wowi, use_unit_id, department_id)
            if not resp:
                return jsonify({"msg": f"Cannot determin official for UseUnit {use_unit_id} "
                                       f"department {department_id}"}), 404
            dest_user_id = resp.erp_user_id

        ticket_source_id = current_app.config["INI_CONFIG"].get("OpenWowi", "ticket_source_id", fallback=None)
        if not ticket_source_id:
            return jsonify({"msg": "The server does not support sending tickets."}), 502
        use_unit_entity_id = current_app.config["INI_CONFIG"].get("OpenWowi", "use_unit_entity_id", fallback=None)

        main_assignment = wowipy.models.TicketAssignment(
            assignment_entity_id=use_unit_entity_id,
            entity_id=use_unit_id
        )

        try:
            rslt = wowi.create_ticket(
                subject=subject,
                content=content,
                source_id=ticket_source_id,
                user_id=dest_user_id,
                main_assignment=main_assignment
            )
        except wowipy.wowipy.WowiPyException as e:
            logger.error(f"route_api_ticket_create: WowipyException while creating ticket: {str(e)}")
            return jsonify({"msg": str(e)}), 502

        if rslt.status_code != 201:
            logger.error(f"route_api_ticket_create: Invaliud status code while creating ticket: "
                         f"Status {rslt.status_code}"
                         f"Message {rslt.message}")
            return jsonify({"msg": rslt.message}), 502

        # PHOTO-HANDLING START
        new_ticket_id = int(rslt.data["Id"])
        files = request.files.getlist("photos[]")
        if len(files) > MAX_FILES:
            return jsonify({"error": f"max {MAX_FILES} photos"}), 400

        saved = []
        for f in files:
            if not f or not f.filename:
                continue

            original = secure_filename(f.filename)
            if not allowed_filename(original):
                return jsonify({"error": f"invalid file type: {original}"}), 400

            ticket_dir = os.path.join(temp_dir, str(use_unit_id))
            os.makedirs(ticket_dir, exist_ok=True)

            ext = Path(original).suffix.lower()
            stored_name = f"{uuid.uuid4().hex}{ext}"
            path = os.path.join(ticket_dir, stored_name)

            f.save(path)
            saved.append({"original": original, "stored": stored_name})
            celery.send_task("tasks.upload_erp_file", args=[new_ticket_id,
                                                            path,
                                                            current_user_id,
                                                            ip_address,
                                                            last_lat,
                                                            last_lon])

            if upload_floor_plan and is_floor_plan_change:
                pic_type = db.session.query(EstatePictureType).filter(EstatePictureType.code == "Groundplan").first()
                med_ent = db.session.query(MediaEntity).filter(MediaEntity.name == "UseUnit").first()
                if not pic_type or not med_ent:
                    logger.error(f"route_api_ticket_create: Cannot upload new groundplan because of missing "
                                 f"picture type or media entity db entry")
                else:
                    celery.send_task("tasks.upload_erp_photo", args=[
                        use_unit_id,
                        path,
                        pic_type.id,
                        med_ent.id,
                        None,
                        current_user_id,
                        ip_address,
                        last_lat,
                        last_lon
                    ])
        # PHOTO-HANDLING END

        return jsonify(rslt.data), rslt.status_code

    @app.route("/app/ticket/catalog", methods=["GET"])
    @jwt_required()
    def route_api_ticket_catalog():
        r_departments = []
        r_officials = []
        departments = (db.session
                       .query(Department)
                       .filter(Department.visible == True)
                       .order_by(Department.name)
                       .all()
                       )
        for dep in departments:
            dep_entry = {
                "id": dep.id,
                "name": dep.name
            }
            r_departments.append(dep_entry)

        officials = (db.session
                     .query(ResponsibleOfficial)
                     .filter(ResponsibleOfficial.visible == True)
                     .order_by(ResponsibleOfficial.name)
                     .all()
                     )
        for off in officials:
            off_entry = {
                "id": off.erp_user_id,
                "name": off.name
            }
            r_officials.append(off_entry)

        return jsonify(
            {
                "departments": r_departments,
                "officials": r_officials
            }
        )

    @app.route("/app/ticket/checklists", methods=["GET"])
    @jwt_required()
    def route_api_ticket_checklists():
        retval = []
        all_lists = db.session.query(CheckList).all()
        for tlist in all_lists:
            list_item = {
                "id": tlist.id,
                "name": tlist.name
            }
            retval.append(list_item)
        return jsonify(retval)

    @app.route("/app/ticket/checklist/<int:checklist_id>", methods=["GET"])
    @jwt_required()
    def route_api_ticket_checklist_details(checklist_id):
        itemlist = []
        checklist_object: CheckList
        checklist_object = db.session.get(CheckList, checklist_id)
        if not checklist_object:
            return abort(404)
        if not checklist_object.check_list_items:
            return jsonify({"msg": "No items in list"}), 404

        entry: CheckListItem
        for entry in checklist_object.check_list_items:
            new_item = {
                "id": entry.id,
                "position": entry.position,
                "description": entry.description,
                "sub_description": entry.sub_description,
                "ticket_subject": entry.ticket_subject,
                "ticket_content": entry.ticket_content,
                "dest_erp_user_id": entry.dest_erp_user_id,
                "dest_erp_department_id": entry.dest_erp_department_id
            }
            itemlist.append(new_item)
        retval = jsonify({
            "checklist": {
                "id": checklist_object.id,
                "name": checklist_object.name
            },
            "items": itemlist
        })
        return retval
