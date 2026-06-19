from flask import jsonify
from flask_jwt_extended import jwt_required
from app.models import ErpUseUnit, ContractPosition
import logging
from app.extensions import db

logger = logging.getLogger()


def register_routes_api_contract(app):
    @app.route("/app/use-unit/<int:use_unit_id>/contract/info", methods=["GET"])
    @jwt_required()
    def app_uu_contract_info(use_unit_id):
        retval = {}
        the_uu = (db.session.query(ErpUseUnit)
                  .filter(ErpUseUnit.erp_id == use_unit_id).first())
        if not the_uu:
            logger.error(f"/app/use-unit/{use_unit_id}/contract/info: Cannot find ErpUseUnit")
            return jsonify(retval)
        contract_positions = (db.session.query(ContractPosition)
                              .filter(ContractPosition.erp_use_unit_id == use_unit_id)
                              .order_by(ContractPosition.amount.desc())
                              .all()
                              )
        cpos_list = []
        if contract_positions:
            for entry in contract_positions:
                cpos_list.append(
                    {
                        "amount": entry.amount,
                        "name": entry.position_type_name
                    }
                )
        retval = jsonify(
            {
                "id": the_uu.erp_contract_id,
                "id_num": the_uu.erp_contract_idnum,
                "contractor1_last": the_uu.contractor_last_name_1,
                "contractor1_first": the_uu.contractor_first_name_1,
                "start": the_uu.contract_start,
                "end": the_uu.contract_end,
                "contract_positions": cpos_list,
                "contract_arrears": the_uu.month_in_arrears
            }
        )
        return retval
