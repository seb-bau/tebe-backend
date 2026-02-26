import logging
import os
from datetime import datetime
import re
from app.extensions import db
from app.models import User, ComponentCatalogItem, EstatePictureType, MediaEntity, EventItem
from app.helpers import normalize_exif_orientation
from wowipy.wowipy import WowiPy, MediaData, FileData
from app.erp import create_facility, create_component, edit_component, with_wowi_retry, WowiPermanentError
from wowicache.models import WowiCache, UseUnit, Building
from flask import current_app

logger = logging.getLogger()


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
    @celery.task(bind=True, name="tasks.upload_erp_photo")
    def upload_erp_photo(self,
                         use_unit_id: int,
                         stored_path: str,
                         picture_type: int,
                         media_entity: int,
                         description: str | None,
                         user_id: int | None,
                         ip_address: str | None,
                         last_lat: str | None,
                         last_lon: str | None):
        try:
            if not os.path.exists(stored_path):
                raise FileNotFoundError(stored_path)

            try:
                normalize_exif_orientation(stored_path)
            except Exception as e:
                logger.warning(f"Could not normalize EXIF orientation for '{stored_path}': {str(e)}")

            def _do(wowi: WowiPy,
                    uu_id: int,
                    media_path: str,
                    pic_type: int,
                    entity: int,
                    desc: str,
                    ):
                ptype = db.session.get(EstatePictureType, pic_type)
                if ptype:
                    picture_type_name = ptype.name
                else:
                    logger.warning(f"task.upload_erp_photo: Using fallback picture type name 'Sonstiges'"
                                   f" because picture type id '{pic_type}' does not exist.")
                    picture_type_name = "Sonstiges"

                ent = db.session.get(MediaEntity, entity)
                if ent:
                    entity_type_name = ent.name
                else:
                    logger.warning(f"task.upload_erp_photo: Using fallback entity 'UseUnit'"
                                   f" because entity id '{entity}' does not exist.")
                    entity_type_name = "UseUnit"

                if entity_type_name == "Building":
                    try:
                        the_uu = wowi.get_use_units(add_args={"useUnitId": uu_id})[0]
                        entity_id = the_uu.building_land.id_
                    except Exception as ex:
                        logger.error(f"task.upload_erp_photo: Building context. Error while getting uu '{uu_id}':"
                                     f"{str(ex)}")
                        raise
                else:
                    entity_id = uu_id
                wowi_file = MediaData(
                    file_name=os.path.basename(media_path),
                    creation_date_str=datetime.now().strftime("%y-%m-%d"),
                    entity_type_name=entity_type_name,
                    entity_id=entity_id,
                    remark=desc
                )
                wowi_file.picture_type_name = picture_type_name
                uplresult = wowi.upload_media(wowi_file, media_path)
                if uplresult.status_code not in [200, 201]:
                    logger.error(f"upload_media failed for entity_id{entity_id}: {uplresult.message}")
                    raise RuntimeError(f"upload_media failed: {uplresult.status_code}")
                logger.info(f"upload_media ok for entityid={entity_id}: {uplresult.message}")

                user = None
                if user_id is not None:
                    user = db.session.get(User, int(user_id))
                    if user:
                        user.last_action = datetime.now()
                        user.last_ip = ip_address
                        user.last_lat = last_lat
                        user.last_lon = last_lon
                        db.session.commit()

                entity_idnum = None
                try:
                    cache = WowiCache(current_app.config['INI_CONFIG'].get("Wowicache", "connection_uri"))
                    if entity_type_name == "UseUnit":
                        cache_uu = cache.session.get(UseUnit, entity_id)
                        if cache_uu:
                            entity_idnum = cache_uu.id_num
                    elif entity_type_name == "Building":
                        cache_buil = cache.session.get(Building, entity_id)
                        if cache_buil:
                            entity_idnum = cache_buil.id_num
                except Exception as ex:
                    logger.error(f"upload_erp_photo: Error while collecting event data: {str(ex)}")

                new_event = EventItem(
                    user_id=user_id,
                    user_name=user.name,
                    action="upl_photo",
                    use_unit_id=entity_id,
                    use_unit_idnum=entity_idnum,
                    last_lat=last_lat,
                    last_lon=last_lon,
                    ip_address=ip_address
                )
                db.session.add(new_event)
                db.session.commit()

            with_wowi_retry(_do,
                            uu_id=use_unit_id,
                            media_path=stored_path,
                            pic_type=picture_type,
                            entity=media_entity,
                            desc=description)

            try:
                os.remove(stored_path)
            except Exception as e:
                logger.warning(f"Could not delete file '{stored_path}': {str(e)}")

            return {"status": "ok"}
        except Exception as e:
            logger.error(f"Task upload_erp_photo failed for use_unit_id={use_unit_id}: {str(e)}")
            raise self.retry(exc=e, countdown=5, max_retries=5)

    @celery.task(bind=True, name="tasks.upload_erp_file")
    def upload_erp_file(self,
                        ticket_id: int,
                        stored_path: str,
                        user_id: int | None,
                        ip_address: str | None,
                        last_lat: str | None,
                        last_lon: str | None):
        try:
            if not os.path.exists(stored_path):
                raise FileNotFoundError(stored_path)

            try:
                normalize_exif_orientation(stored_path)
            except Exception as e:
                logger.warning(f"Could not normalize EXIF orientation for '{stored_path}': {str(e)}")

            def _do(wowi: WowiPy,
                    tick_id: int,
                    file_path: str,
                    ):

                wowi_file = FileData(
                    file_name=os.path.basename(file_path),
                    creation_date_str=datetime.now().strftime("%y-%m-%d"),
                    entity_type_name="Ticket",
                    file_type_name="Nachrichten-Anhang",
                    entity_id=tick_id
                )
                uplresult = wowi.upload_file(wowi_file, file_path)
                if uplresult.status_code not in [200, 201]:
                    logger.error(f"upload_erp_file failed for ticket_id {tick_id}: {uplresult.message}")
                    raise RuntimeError(f"upload_erp_file failed for ticket_id {tick_id}: {uplresult.message}")
                logger.info(f"upload_media ok for ticket_id={tick_id}: {uplresult.message}")

                user = None
                if user_id is not None:
                    user = db.session.get(User, int(user_id))
                    if user:
                        user.last_action = datetime.now()
                        user.last_ip = ip_address
                        user.last_lat = last_lat
                        user.last_lon = last_lon
                        db.session.commit()

                new_event = EventItem(
                    user_id=user_id,
                    user_name=user.name,
                    action="upl_file",
                    use_unit_id=tick_id,
                    last_lat=last_lat,
                    last_lon=last_lon,
                    ip_address=ip_address
                )
                db.session.add(new_event)
                db.session.commit()

            with_wowi_retry(_do, tick_id=ticket_id, file_path=stored_path,)

            try:
                os.remove(stored_path)
            except Exception as e:
                logger.warning(f"Could not delete file '{stored_path}': {str(e)}")

            return {"status": "ok"}
        except Exception as e:
            logger.error(f"Task upload_erp_file failed for ticket_id={ticket_id}: {str(e)}")
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
