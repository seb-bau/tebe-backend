from flask import abort
from flask_jwt_extended import jwt_required
from wowipy.wowipy import WowiPy, LicenseAgreement
import wowipy.models
from flask import current_app
from app.erp import with_wowi_retry
from datetime import datetime
import logging
from app.helpers import _json_from_file

logger = logging.getLogger()


def register_routes_api_contacts(app):
    @app.route("/app/use-unit/contacts/<int:use_unit_id>", methods=["GET"])
    @jwt_required()
    def app_uu_contact(use_unit_id):
        if current_app.config['DEMO_MODE']:
            return _json_from_file(current_app.config['DEMO_CONTACTS'])

        def _do_app_uu_contact(wowi: WowiPy, uu_id: int):
            contracts = wowi.get_license_agreements(license_agreement_active_on=datetime.now(),
                                                    add_args={"useUnitId": uu_id},
                                                    add_contractors=True
                                                    )
            if not contracts:
                return abort(404)
            the_contract: LicenseAgreement
            the_contract = contracts[0]
            if the_contract.restriction_of_use.is_vacancy:
                return abort(404)
            if not the_contract.contractors:
                return abort(404)

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

                try:
                    person_email = the_person.first_email_communication.content or None
                except AttributeError:
                    person_email = None
                try:
                    person_phone = the_person.first_landline_phone_communication.content or None
                except AttributeError:
                    person_phone = None
                try:
                    person_mobile = the_person.first_mobile_phone_communication.content or None
                except AttributeError:
                    person_mobile = None
                try:
                    person_role = contractor_entry.contractor_type.name
                except (ValueError, AttributeError):
                    person_role = None

                # Auch sekundäre Rufnummern übertragen
                additional_numbers = []
                communications = the_person.communications
                if communications:
                    for com_entry in communications:
                        if com_entry.communication_type.id_ == 1 or com_entry.communication_type.id_ == 3:
                            content = com_entry.content
                            if content != person_phone and content != person_mobile:
                                additional_numbers.append(content)

                if person_email or person_phone or person_mobile:
                    contact_entry = {
                        "role": person_role,
                        "name": person_name,
                        "gender": person_gender,
                        "email": person_email,
                        "phone": person_phone,
                        "mobile": person_mobile,
                        "birth_date": person_birth_date,
                        "additional_numbers": additional_numbers
                    }
                    contact_items.append(contact_entry)
            if not contact_items:
                return abort(404)
            else:
                return {
                    "contact_items": contact_items
                }

        oretval = with_wowi_retry(_do_app_uu_contact, uu_id=use_unit_id)
        return oretval
