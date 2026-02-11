import logging
import os
from datetime import datetime
import re
from app.extensions import db
from app.models import User, ComponentCatalogItem
from app.helpers import normalize_exif_orientation
from wowipy.wowipy import WowiPy, MediaData
from app.erp import create_facility, create_component, edit_component, with_wowi_retry, WowiPermanentError


logger = logging.getLogger("root")


class PermanentRequestError(Exception):
    pass


def _extract_http_status(exc) -> int | None:
    code = getattr(exc, "status_code", None)
    if code is not None:
        try:
            return int(code)
        except Exception as e:
            print(str(e))
            pass

    m = re.match(r"^\s*(\d{3})\s*:", str(exc))
    if m:
        try:
            return int(m.group(1))
        except Exception as e:
            print(str(e))
            return None
    return None


def _is_permanent_http_error(exc) -> bool:
    status = _extract_http_status(exc)
    return bool(status is not None and 400 <= status < 500 and status not in (401, 403, 429))


def register_tasks(celery):
    @celery.task(bind=True, name="tasks.upload_use_unit_photo")
    def upload_use_unit_photo(self, use_unit_id: int, stored_path: str):
        try:
            if not os.path.exists(stored_path):
                raise FileNotFoundError(stored_path)

            try:
                normalize_exif_orientation(stored_path)
            except Exception as e:
                logger.warning(f"Could not normalize EXIF orientation for '{stored_path}': {str(e)}")

            def _do(wowi: WowiPy, uu_id: int, media_path: str):
                wowi_file = MediaData(
                    file_name=os.path.basename(media_path),
                    creation_date_str=datetime.now().strftime("%y-%m-%d"),
                    entity_type_name="UseUnit",
                    entity_id=uu_id
                )
                wowi_file.picture_type_name = "Sonstiges"
                uplresult = wowi.upload_media(wowi_file, media_path)
                if uplresult.status_code not in [200, 201]:
                    logger.error(f"upload_media failed for use_unit_id={uu_id}: {uplresult.message}")
                    raise RuntimeError(f"upload_media failed: {uplresult.status_code}")
                logger.info(f"upload_media ok for use_unit_id={uu_id}: {uplresult.message}")

            with_wowi_retry(_do, uu_id=use_unit_id, media_path=stored_path)

            try:
                os.remove(stored_path)
            except Exception as e:
                logger.warning(f"Could not delete file '{stored_path}': {str(e)}")

            return {"status": "ok"}
        except Exception as e:
            logger.error(f"Task upload_use_unit_photo failed for use_unit_id={use_unit_id}: {str(e)}")
            raise self.retry(exc=e, countdown=5, max_retries=5)

    @celery.task(bind=True, name="tasks.write_use_unit_data")
    def write_use_unit_data(
        self,
        use_unit_id: int,
        payload: list[dict],
        user_id: int | None,
        ip_address: str | None,
        last_lat: str | None,
        last_lon: str | None,
    ):
        try:
            def _do(wowi: WowiPy, uu_id: int):
                components_updated = 0
                components_created = 0
                facilities_created = 0
                components_deleted = 0

                user = None
                if user_id is not None:
                    user = User.query.get(int(user_id))
                    if user:
                        user.last_action = datetime.now()
                        user.last_ip = ip_address
                        user.last_lat = last_lat
                        user.last_lon = last_lon
                        db.session.commit()

                for entry in payload:
                    comp_cat_id = entry.get("component_catalog_id")
                    if not comp_cat_id:
                        raise PermanentRequestError("missing component_catalog_id")

                    comp_cat_item = db.session.get(ComponentCatalogItem, comp_cat_id)
                    if not comp_cat_item:
                        raise PermanentRequestError(f"unknown component_catalog_id={comp_cat_id}")

                    if not comp_cat_item.enabled:
                        raise PermanentRequestError(f"component_catalog_id disabled={comp_cat_id}")

                    qty = entry.get("quantity")
                    if not isinstance(qty, (int, float)):
                        raise PermanentRequestError("quantity has to be numeric")

                    comment = entry.get("comment")
                    psub = entry.get("sub_components") or []

                    component_id = entry.get("component_id")
                    if not component_id:
                        if entry.get("is_unknown"):
                            continue

                        uu_facilities = wowi.get_facilities(use_unit_id=uu_id)
                        uu_facility = None
                        for fac_entry in uu_facilities:
                            if fac_entry.facility_catalog_id == comp_cat_item.facility_catalog_item_id:
                                uu_facility = fac_entry.id_
                                break

                        if not uu_facility:
                            uu_facility = create_facility(wowi, comp_cat_item.facility_catalog_item_id, uu_id)
                            facilities_created += 1

                        if not uu_facility:
                            raise RuntimeError("Error while creating facility")

                        new_component_id = create_component(
                            wowi,
                            component_catalog_id=comp_cat_item.id,
                            facility_id=uu_facility,
                            count=int(qty),
                            psub_components=psub,
                            puser=user,
                            puu_id=uu_id,
                            comment=comment,
                            ip_address=ip_address,
                            last_lat=last_lat,
                            last_lon=last_lon,
                        )
                        components_created += 1
                        if not new_component_id:
                            raise RuntimeError("Error while creating component")
                        logger.info(f"Created component {new_component_id} for use_unit_id={uu_id}")
                    else:
                        unknown = bool(entry.get("is_unknown"))
                        r = edit_component(
                            wowi,
                            component_id=int(component_id),
                            count=int(qty),
                            psub_components=psub,
                            unknown=unknown,
                            comment=comment,
                            puser=user,
                            ip_address=ip_address,
                            last_lat=last_lat,
                            last_lon=last_lon,
                        )
                        if r is None:
                            raise RuntimeError("Error while editing component")
                        if not unknown:
                            components_updated += 1
                        else:
                            components_deleted += 1

                db.session.commit()
                return {
                    "facilities_created": facilities_created,
                    "components_created": components_created,
                    "components_updated": components_updated,
                    "components_deleted": components_deleted,
                }

            result = with_wowi_retry(_do, uu_id=use_unit_id)
            return {"status": "ok", "result": result}

        except (PermanentRequestError, WowiPermanentError) as e:
            logger.error(f"Permanent error in write_use_unit_data for use_unit_id={use_unit_id}: {str(e)}")
            return {"status": "failed", "reason": "permanent", "error": str(e)}
        except Exception as e:
            if _is_permanent_http_error(e):
                logger.error(
                    f"Permanent HTTP error in write_use_unit_data for use_unit_id={use_unit_id}: {str(e)}"
                )
                raise PermanentRequestError(str(e))

            logger.error(
                f"Transient error in write_use_unit_data failed for use_unit_id={use_unit_id}: {str(e)}"
            )
            raise self.retry(exc=e, countdown=5, max_retries=5)
