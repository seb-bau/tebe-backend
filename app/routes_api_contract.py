from configparser import ConfigParser

from flask import jsonify, current_app
from flask_jwt_extended import jwt_required
from app.models import ErpUseUnit, ContractPosition
import logging
from app.extensions import db
from decimal import Decimal

logger = logging.getLogger()


def get_config() -> ConfigParser:
    return current_app.config["INI_CONFIG"]


def get_rent_per_square_meter(cont_positions: list, living_space: Decimal) -> dict:
    config = get_config()
    rent_mode = config.get("Handling", "rent_per_sqm_mode", fallback="net")
    relevant_positions_raw = config.get("Handling", "rent_per_sqm_positions", fallback="")
    relevant_positions = [
        position.strip().casefold()
        for position in relevant_positions_raw.split("|")
        if position.strip()
    ]

    if not cont_positions or not living_space:
        return {
            "mode": rent_mode,
            "rent_per_sqm": Decimal("0.00")
        }

    rent_sum = Decimal("0.00")
    entry: ContractPosition
    for entry in cont_positions:
        position_type_name = (entry.position_type_name or "").casefold()

        if not relevant_positions or position_type_name in relevant_positions:
            rent_sum += Decimal(entry.amount)

    return {
        "mode": rent_mode,
        "rent_per_sqm": round(rent_sum / living_space, 2)
    }


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
                        "amount": round(entry.amount, 2),
                        "name": entry.position_type_name
                    }
                )
        try:
            rpsqm = get_rent_per_square_meter(contract_positions, the_uu.living_space)
        except Exception as e:
            logger.error(f"Exception while getting rpsqm: {str(e)}")
            rpsqm = {"mode": "net", "rent_per_sqm": Decimal("0.00")}

        retval = jsonify(
            {
                "id": the_uu.erp_contract_id,
                "id_num": the_uu.erp_contract_idnum,
                "contractor1_last": the_uu.contractor_last_name_1,
                "contractor1_first": the_uu.contractor_first_name_1,
                "start": the_uu.contract_start,
                "end": the_uu.contract_end,
                "contract_positions": cpos_list,
                "contract_arrears": round(the_uu.month_in_arrears, 2),
                "rent_per_sqm": rpsqm.get("rent_per_sqm"),
                "rent_per_sqm_mode": rpsqm.get("mode"),
                "living_space": round(the_uu.living_space, 2)
            }
        )
        return retval
