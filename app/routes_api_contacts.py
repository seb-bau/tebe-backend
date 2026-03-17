from flask import abort, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from wowipy.models import Communication
from wowipy.wowipy import WowiPy, LicenseAgreement
import wowipy.models
from flask import current_app
from app.erp import with_wowi_retry
from app.models import User, EventItem
from datetime import datetime
import logging
from app.helpers import _json_from_file
import re
from typing import Optional
from app.payloads import store_payload
from app.extensions import db

logger = logging.getLogger()


def get_current_user() -> User:
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    return user


def get_comm_details(wowi: WowiPy, person_id: int, comm_id: int) -> Communication | None:
    the_person = wowi.get_persons(person_id=person_id)[0]
    for centry in the_person.communications:
        if centry.id_ == comm_id:
            return centry
    return None


def wowi_get_current_address_id(wowi: WowiPy, person_id: int) -> int | None:
    the_person = wowi.get_persons(person_id=person_id)[0]
    for addr in the_person.addresses:
        addr_from = datetime.strptime(str(addr.valid_from), "%Y-%m-%d")
        addr_to = None
        if addr.valid_to is not None:
            addr_to = datetime.strptime(str(addr.valid_to), "%Y-%m-%d")
        if addr_from < datetime.now() and (addr_to is None or addr_to > datetime.now()):
            return addr.id_
    return None


CHANGE_COMMENT_PATTERN = re.compile(
    r"\s*\[TEBE_APP_CHANGED_BY:[^]]*]\s*",
    re.IGNORECASE
)


def build_change_comment(full_name: str) -> str:
    return f"[TEBE_APP_CHANGED_BY: {full_name}]"


def strip_change_comments(comment: Optional[str]) -> str:
    if not comment:
        return ""

    cleaned = CHANGE_COMMENT_PATTERN.sub(" ", comment)
    return " ".join(cleaned.split()).strip()


def has_change_comment(comment: Optional[str]) -> bool:
    if not comment:
        return False

    return CHANGE_COMMENT_PATTERN.search(comment) is not None


def extract_change_comments(comment: Optional[str]) -> list[str]:
    if not comment:
        return []

    return CHANGE_COMMENT_PATTERN.findall(comment)


def prepare_comment_for_display(comment_from_erp: Optional[str]) -> str:
    return strip_change_comments(comment_from_erp)


def prepare_comment_for_save(
    user_comment: Optional[str],
    full_name: str,
) -> str:
    base_comment = strip_change_comments(user_comment)
    change_comment = build_change_comment(full_name)

    if base_comment:
        return f"{base_comment} {change_comment}"

    return change_comment


def replace_change_comment(
    comment: Optional[str],
    full_name: str,
) -> str:
    """
    Entfernt vorhandene technische Kommentare und setzt genau einen neuen.
    Praktisch, wenn der Kommentar bereits direkt aus dem ERP kommt.
    """
    return prepare_comment_for_save(comment, full_name)


def register_routes_api_contacts(app):
    @app.route("/app/use-unit/contacts/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_contact(use_unit_id):
        fallback = jsonify({"contact_items": []})
        if current_app.config['DEMO_MODE']:
            return _json_from_file(current_app.config['DEMO_CONTACTS'])

        def _do_app_uu_contact(wowi: WowiPy, uu_id: int):
            contracts = wowi.get_license_agreements(license_agreement_active_on=datetime.now(),
                                                    add_args={"useUnitId": uu_id},
                                                    add_contractors=True
                                                    )

            def get_comm_items_of_type(type_ids: list[int], comm_items) -> list[Communication]:
                retval = []
                if comm_items:
                    for c_entry in comm_items:
                        if c_entry.communication_type.id_ in type_ids:
                            retval.append(c_entry)
                return retval

            if not contracts:
                return fallback
            the_contract: LicenseAgreement
            the_contract = contracts[0]
            if the_contract.restriction_of_use.is_vacancy:
                return fallback
            if not the_contract.contractors:
                return fallback

            contact_items = []
            contractor_entry: wowipy.wowipy.Contractor
            for contractor_entry in the_contract.contractors:
                the_person = contractor_entry.person
                if the_person.is_natural_person:
                    np = the_person.natural_person
                    title = f"{np.title} " if np.title else ""
                    person_name = f"{title}{np.last_name}, {np.first_name}"
                    person_gender = np.gender.name
                    try:
                        if isinstance(np.birth_date, str):
                            person_birth_date = np.birth_date
                        elif isinstance(np.birth_date, datetime):
                            person_birth_date = np.birth_date.strftime("%Y-%m-%d")
                        else:
                            person_birth_date = None
                    except (TypeError, AttributeError):
                        person_birth_date = None
                else:
                    person_name = the_person.legal_person.long_name1
                    person_gender = None
                    person_birth_date = None

                communications = the_person.communications

                person_email = None
                person_email_id = None
                person_email_comment = None
                person_phone = None
                person_phone_id = None
                person_phone_comment = None
                person_mobile = None
                person_mobile_id = None
                person_mobile_comment = None
                person_role = None

                # EMAIL
                try:
                    person_email = the_person.first_email_communication.content or None
                    person_email_id = the_person.first_email_communication.id_ or None
                    person_email_comment = prepare_comment_for_display(
                        the_person.first_email_communication.explanation or None)
                except AttributeError:
                    pass

                if not person_email:
                    try:
                        person_email = get_comm_items_of_type([5], communications)[0].content
                        person_email_id = get_comm_items_of_type([5], communications)[0].id_
                        person_email_comment = prepare_comment_for_display(
                            get_comm_items_of_type([5], communications)[0].explanation)
                    except Exception as e:
                        _ = e

                # PHONE
                try:
                    person_phone = the_person.first_landline_phone_communication.content or None
                    person_phone_id = the_person.first_landline_phone_communication.id_ or None
                    person_phone_comment = prepare_comment_for_display(
                        the_person.first_landline_phone_communication.explanation or None)
                except AttributeError:
                    pass
                if not person_phone:
                    try:
                        person_phone = get_comm_items_of_type([1], communications)[0].content
                        person_phone_id = get_comm_items_of_type([1], communications)[0].id_
                        person_phone_comment = prepare_comment_for_display(
                            get_comm_items_of_type([1], communications)[0].explanation)
                    except Exception as e:
                        _ = e

                # MOBILE
                try:
                    person_mobile = the_person.first_mobile_phone_communication.content or None
                    person_mobile_id = the_person.first_mobile_phone_communication.id_ or None
                    person_mobile_comment = prepare_comment_for_display(
                        the_person.first_mobile_phone_communication.explanation or None)
                except AttributeError:
                    pass

                if not person_mobile:
                    try:
                        person_mobile = get_comm_items_of_type([3], communications)[0].content
                        person_mobile_id = get_comm_items_of_type([3], communications)[0].id_
                        person_mobile_comment = prepare_comment_for_display(
                            get_comm_items_of_type([3], communications)[0].explanation)
                    except Exception as e:
                        _ = e

                # ROLE
                try:
                    person_role = contractor_entry.contractor_type.name
                except (ValueError, AttributeError):
                    pass

                # Auch sekundäre Rufnummern übertragen
                additional_numbers = []
                more_items = get_comm_items_of_type([1, 3], communications)
                if more_items:
                    for com_entry in more_items:
                        content = com_entry.content
                        if content != person_phone and content != person_mobile:
                            additional_numbers.append(content)

                contact_entry = {
                    "person_id": the_person.id_,
                    "role": person_role,
                    "name": person_name,
                    "gender": person_gender,
                    "email": person_email,
                    "email_id": person_email_id,
                    "email_comment": person_email_comment,
                    "phone": person_phone,
                    "phone_id": person_phone_id,
                    "phone_comment": person_phone_comment,
                    "mobile": person_mobile,
                    "mobile_id": person_mobile_id,
                    "mobile_comment": person_mobile_comment,
                    "birth_date": person_birth_date,
                    "additional_numbers": additional_numbers
                }
                contact_items.append(contact_entry)
            if not contact_items:
                return fallback
            else:
                return {
                    "contact_items": contact_items
                }

        oretval = with_wowi_retry(_do_app_uu_contact, uu_id=use_unit_id)
        return oretval

    @app.route("/app/person/<int:person_id>/communication", methods=["POST"])
    @jwt_required()
    def app_person_communication_write(person_id):
        if current_app.config['DEMO_MODE']:
            return jsonify({"msg": "ok"})

        store_payload()

        def _do_app_person_communication_write(wowi: WowiPy, per_id: int, type_id: int | None,
                                               comm_id: int | None, comm_content: str, comm_comment: str | None,
                                               user: User):

            comm_comment = prepare_comment_for_save(comm_comment, user.name)

            if comm_id is None:
                # Kein Bezug auf bestehenden Kommunikationseintrag: Neuen erstellen
                addr_to_connect = wowi_get_current_address_id(wowi, per_id)
                wowi.create_communication(person_id=per_id,
                                          communication_type_id=type_id,
                                          related_address_id=addr_to_connect,
                                          content=comm_content,
                                          explanation=comm_comment)
                nevent = EventItem(
                    user_id=user.id,
                    user_name=user.name,
                    action="add_comm",
                    use_unit_id=person_id,
                )
                db.session.add(nevent)
                db.session.commit()
                return jsonify({"msg": "ok"}), 201
            else:
                # Wir haben eine comm-id, die angepasst werden soll
                comm_details = get_comm_details(wowi, per_id, comm_id)
                if not comm_details:
                    logger.error(f"app_person_write: Comm Entry '{comm_id}' should be edited "
                                 f"but was not found for person '{per_id}'")
                    return abort(500)
                wowi.edit_communication(person_id=per_id,
                                        communication_id=comm_id,
                                        communication_type_id=comm_details.communication_type.id_,
                                        related_address_id=comm_details.related_address_id,
                                        content=comm_content,
                                        explanation=comm_comment)
                nevent = EventItem(
                    user_id=user.id,
                    user_name=user.name,
                    action="edit_comm",
                    use_unit_id=person_id,
                )
                db.session.add(nevent)
                db.session.commit()
                return jsonify({"msg": "ok"}), 200

        communication_id_r = request.form.get("communication_id")
        communication_type_id_r = request.form.get("communication_type_id")
        communication_content = request.form.get("communication_content")
        communication_comment = request.form.get("communication_comment")
        communication_id = None
        communication_type_id = None

        if communication_type_id_r:
            try:
                communication_type_id = int(communication_type_id_r)
            except (ValueError, TypeError):
                pass

        if communication_id_r:
            try:
                communication_id = int(communication_id_r)
            except (ValueError, TypeError):
                pass

        if not communication_id and not communication_type_id:
            logger.error(f"app_person_write: Cannot add communication entry for person '{person_id}' because neither "
                         f"existing id nor new type was given")
            return abort(400)

        if not communication_content:
            logger.error(f"app_person_write: Empty content for person '{person_id}'")
            return abort(400)

        # config = current_app.config['INI_CONFIG']

        the_user = get_current_user()

        oretval = with_wowi_retry(_do_app_person_communication_write, per_id=person_id, type_id=communication_type_id,
                                  comm_id=communication_id, comm_content=communication_content,
                                  comm_comment=communication_comment, user=the_user)
        return oretval

    @app.route("/app/person/<int:person_id>/communication/<int:communication_id>", methods=["DELETE"])
    @jwt_required()
    def app_person_communication_delete(person_id, communication_id):
        if current_app.config['DEMO_MODE']:
            return jsonify({"msg": "ok"})

        store_payload()
        the_user = get_current_user()
        nevent = EventItem(
            user_id=the_user.id,
            user_name=the_user.name,
            action="del_comm",
            use_unit_id=person_id,
        )
        db.session.add(nevent)
        db.session.commit()

        def _do_app_person_communication_delete(wowi: WowiPy, per_id: int, comm_id: int):
            wowi.delete_communication(per_id, comm_id)

        with_wowi_retry(_do_app_person_communication_delete, per_id=person_id, comm_id=communication_id)
        return jsonify({"msg": "ok"})
