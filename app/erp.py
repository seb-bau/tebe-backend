from wowipy.wowipy import WowiPy, Result
from wowipy.models import (FacilityCatalogElement, ComponentCatalogElement, UnderComponentCatalogElement,
                           FacilityElement)
from flask import current_app
import logging
from app.extensions import db
from app.models import (FacilityCatalogItem, ComponentCatalogItem, UnderComponentItem, EventItem, User, FacilityItem,
                        EstatePictureType, MediaEntity)
from threading import Lock
from datetime import datetime
import re

logger = logging.getLogger()


class WowiPermanentError(Exception):
    pass


class WowiTransientError(Exception):
    pass


class WowiAuthError(Exception):
    pass


_wowi_client = None
_wowi_lock = Lock()


def get_wowi_client():
    global _wowi_client

    if _wowi_client is not None:
        return _wowi_client

    with _wowi_lock:
        if _wowi_client is None:
            config = current_app.config["INI_CONFIG"]
            host = config.get("OpenWowi", "host")
            user = config.get("OpenWowi", "user")
            password = config.get("OpenWowi", "pass")
            key = config.get("OpenWowi", "key")

            logger.info("Creating new WowiPy client for OpenWowi host '%s'", host)
            client = WowiPy(host, user, password, key)

            _wowi_client = client

    return _wowi_client


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


def with_wowi_retry(fn, *args, **kwargs):
    global _wowi_client

    client = get_wowi_client()

    try:
        return fn(client, *args, **kwargs)

    except WowiAuthError as exc:
        logger.info("WowiPy auth failed, resetting client: %s", exc)

        with _wowi_lock:
            _wowi_client = None

        client = get_wowi_client()
        return fn(client, *args, **kwargs)

    except Exception as exc:

        status = _extract_http_status(exc)

        # 4xx = permanent -> KEIN retry (außer evtl. auth/rate limit)

        if status is not None and 400 <= status < 500 and status not in (401, 403, 429):
            raise

        logger.info("WowiPy call failed, attempting retry: %s", exc)

        with _wowi_lock:

            _wowi_client = None

        client = get_wowi_client()

        return fn(client, *args, **kwargs)


def _raise_for_result(op_name: str, result: Result):
    status = getattr(result, "status_code", None)
    msg = getattr(result, "message", None)

    if status is None:
        raise WowiTransientError(f"{op_name}: missing status_code")

    status = int(status)

    if 200 <= status < 300:
        return

    if status in (401, 403):
        raise WowiAuthError(f"{op_name}: {status} {msg}")

    if 400 <= status < 500:
        raise WowiPermanentError(f"{op_name}: {status} {msg}")

    raise WowiTransientError(f"{op_name}: {status} {msg}")


def sync_facility_catalog(wowi: WowiPy):
    facility_catalog_items = wowi.get_facility_catalog()
    fac_cat_ids = []
    entry: FacilityCatalogElement
    for entry in facility_catalog_items:
        fac_cat_ids.append(entry.id_)
        find_facility = db.session.get(FacilityCatalogItem, entry.id_)
        if find_facility:
            find_facility.name = entry.name
            find_facility.status_name = entry.status_name
            find_facility.status_id = entry.status_id
            find_facility.available_building = entry.available_building
            find_facility.available_use_unit = entry.available_use_unit
            find_facility.available_economic_unit_land = entry.available_economic_unit_land
            find_facility.repair_relevance = entry.repair_relevance
        else:
            find_facility = FacilityCatalogItem(
                id=entry.id_,
                name=entry.name,
                status_name=entry.status_name,
                status_id=entry.status_id,
                available_building=entry.available_building,
                available_use_unit=entry.available_use_unit,
                available_economic_unit_land=entry.available_economic_unit_land,
                repair_relevance=entry.repair_relevance
            )
            db.session.add(find_facility)
        db.session.commit()

    all_fac_cats = db.session.query(FacilityCatalogItem).all()
    for fac_cat_check in all_fac_cats:
        if fac_cat_check.id not in fac_cat_ids:
            db.session.delete(fac_cat_check)
    db.session.commit()


def sync_facility_items(wowi: WowiPy):
    all_facilities = wowi.get_facilities(fetch_all=True)
    fac_ids = []
    entry_fac: FacilityElement
    for entry_fac in all_facilities:
        fac_ids.append(entry_fac.id_)
        find_fac = db.session.get(FacilityItem, entry_fac.id_)
        if find_fac:
            find_fac.name = entry_fac.name
            find_fac.facility_catalog_item_id = entry_fac.facility_catalog_id
        else:
            find_fac = FacilityItem(
                id=entry_fac.id_,
                name=entry_fac.name,
                facility_catalog_item_id=entry_fac.facility_catalog_id
            )
            db.session.add(find_fac)
        db.session.commit()

    all_facs = db.session.query(FacilityItem).all()
    for fac_check in all_facs:
        if fac_check.id not in fac_ids:
            db.session.delete(fac_check)
    db.session.commit()


def sync_component_catalog(wowi: WowiPy):
    component_catalog_items = wowi.get_component_catalog()
    comp_cat_ids = []
    entry2: ComponentCatalogElement
    for entry2 in component_catalog_items:
        comp_cat_ids.append(entry2.id_)
        find_component = db.session.get(ComponentCatalogItem, entry2.id_)
        if find_component:
            find_component.name = entry2.name
            find_component.comment = entry2.comment
            find_component.is_maintenance_relevant = entry2.is_maintenance_relevant
            find_component.is_repair_relevant = entry2.is_repair_relevant
            find_component.is_lease_relevant = entry2.is_lease_relevant
            find_component.is_warranty_relevant = entry2.is_warranty_relevant
            find_component.quantity_type_id = entry2.quantity_type_id
            find_component.quantity_type_name = entry2.quantity_type_name
            find_component.quantity_type_code = entry2.quantity_type_code
            find_component.is_metering_device = entry2.is_metering_device
            find_component.facility_catalog_item_id = entry2.facility_catalog_id
        else:
            find_component = ComponentCatalogItem(
                id=entry2.id_,
                name=entry2.name,
                comment=entry2.comment,
                is_maintenance_relevant=entry2.is_maintenance_relevant,
                is_repair_relevant=entry2.is_repair_relevant,
                is_lease_relevant=entry2.is_lease_relevant,
                is_warranty_relevant=entry2.is_warranty_relevant,
                quantity_type_id=entry2.quantity_type_id,
                quantity_type_name=entry2.quantity_type_name,
                quantity_type_code=entry2.quantity_type_code,
                is_metering_device=entry2.is_metering_device,
                facility_catalog_item_id=entry2.facility_catalog_id
            )
            db.session.add(find_component)
        db.session.commit()

    all_comp_cats = db.session.query(ComponentCatalogItem).all()
    for comp_cat_check in all_comp_cats:
        if comp_cat_check.id not in comp_cat_ids:
            db.session.delete(comp_cat_check)
    db.session.commit()


def sync_under_component_catalog(wowi: WowiPy):
    under_component_catalog_items = wowi.get_under_component_catalog()
    under_comp_cat_ids = []
    entry3: UnderComponentCatalogElement
    for entry3 in under_component_catalog_items:
        under_comp_cat_ids.append(entry3.id_)
        find_under_component = db.session.get(UnderComponentItem, entry3.id_)
        if find_under_component:
            find_under_component.name = entry3.name
        else:
            find_under_component = UnderComponentItem(
                id=entry3.id_,
                name=entry3.name
            )
            db.session.add(find_under_component)
        db.session.commit()

    all_under = db.session.query(UnderComponentItem).all()
    for under_check in all_under:
        if under_check.id not in under_comp_cat_ids:
            db.session.delete(under_check)
    db.session.commit()


def sync_estate_picture_types(wowi: WowiPy):
    estate_picture_types = wowi.get_estate_picture_types()
    picture_type_ids = []
    for entry3 in estate_picture_types:
        picture_type_ids.append(entry3.id_)
        find_pic_type = db.session.get(EstatePictureType, entry3.id_)
        if find_pic_type:
            find_pic_type.name = entry3.name
            find_pic_type.code = entry3.code
        else:
            find_pic_type = EstatePictureType(
                id=entry3.id_,
                name=entry3.name,
                code=entry3.code
            )
            db.session.add(find_pic_type)
        db.session.commit()

    all_pic_types = db.session.query(EstatePictureType).all()
    for pic_check in all_pic_types:
        if pic_check.id not in picture_type_ids:
            db.session.delete(pic_check)
    db.session.commit()


def sync_media_entities(wowi: WowiPy):
    media_entities = wowi.get_media_entities()
    media_ids = []
    for entry3 in media_entities:
        media_ids.append(entry3.id_)
        find_type = db.session.get(MediaEntity, entry3.id_)
        if find_type:
            find_type.name = entry3.name
        else:
            find_type = MediaEntity(
                id=entry3.id_,
                name=entry3.name
            )
            db.session.add(find_type)
        db.session.commit()

    all_types = db.session.query(MediaEntity).all()
    for type_check in all_types:
        if type_check.id not in media_ids:
            db.session.delete(type_check)
    db.session.commit()


def sync_erp_data():
    wowi = get_wowi_client()
    sync_facility_catalog(wowi)
    sync_facility_items(wowi)
    sync_component_catalog(wowi)
    sync_under_component_catalog(wowi)
    sync_estate_picture_types(wowi)
    sync_media_entities(wowi)


def create_facility(wowi: WowiPy, facility_catalog_id: int, use_unit_id: int) -> int:
    config = current_app.config["INI_CONFIG"]
    facility_cat_item: FacilityCatalogItem
    facility_cat_item = db.session.get(FacilityCatalogItem, facility_catalog_id)

    cr_f_result = wowi.create_facility(
        name=facility_cat_item.name,
        count=1,
        facility_catalog_id=facility_cat_item.id,
        facility_status_id=config.get("Handling", "component_status"),
        use_unit_id=use_unit_id
    )
    _raise_for_result("create_facility", cr_f_result)
    logger.info(f"create_facility: Use Unit '{use_unit_id}' "
                f"facility '{cr_f_result.data['Id']}' with name '{facility_cat_item.name}' created. ")

    new_facility_for_cache = FacilityItem(
        id=cr_f_result.data["Id"],
        name=facility_cat_item.name,
        facility_catalog_item_id=facility_cat_item.id
    )
    db.session.add(new_facility_for_cache)
    db.session.commit()
    return cr_f_result.data["Id"]


def create_component(
    wowi: WowiPy,
    component_catalog_id: int,
    facility_id: int,
    count: int,
    puser: User,
    puu_id: int,
    psub_components: list[int] = None,
    comment: str = None,
    ip_address: str | None = None,
    last_lat: str | None = None,
    last_lon: str | None = None,
) -> int | None:
    config = current_app.config["INI_CONFIG"]
    dest_component_status = config.get("Handling", "component_status")
    bool_handling = config.get("Handling", "bool_handling")
    component_cat_item: ComponentCatalogItem
    component_cat_item = db.session.get(ComponentCatalogItem, component_catalog_id)

    if component_cat_item.is_bool:
        sub_components = []
    else:
        sub_components = psub_components or []

    if component_cat_item.is_bool and bool_handling == "sub_components":
        if count > 1:
            logger.error(f"create_component: facility_id: {facility_id} compcat {component_catalog_id} "
                         f"invalid count {count} for bool component!")
            return None
        if count == 1:
            sub_components.append(config.getint("Handling", "bool_sub_component_yes_id"))
        else:
            sub_components.append(config.getint("Handling", "bool_sub_component_no_id"))

    cr_f_result = wowi.create_component(
        name=component_cat_item.name,
        count=count,
        component_catalog_id=component_cat_item.id,
        component_status_id=dest_component_status,
        facility_id=facility_id,
        under_component_ids=sub_components,
        comment=comment
    )
    _raise_for_result("create_component", cr_f_result)
    logger.info(f"create_component: Use Unit '{puu_id}' "
                f"component '{cr_f_result.data['Id']}' created. Count: {count} "
                f"facility_id: {facility_id} under_component_ids: '{str(sub_components)}' "
                f"comment '{comment}'")

    new_event = EventItem(
        user_id=puser.id,
        user_name=puser.name,
        action="create",
        ip_address=ip_address,
        last_lat=last_lat,
        last_lon=last_lon,
        use_unit_id=puu_id,
        facility_id=facility_id,
        facility_catalog_id=component_cat_item.facility_catalog_item_id,
        component_id=cr_f_result.data["Id"],
        component_catalog_id=component_cat_item.id,
        sub_component_ids=",".join(str(e) for e in sub_components) if sub_components else None
    )
    db.session.add(new_event)
    db.session.commit()
    return cr_f_result.data["Id"]


def edit_component(
    wowi: WowiPy,
    component_id: int,
    count: int,
    psub_components: list[int] = None,
    unknown: bool = False,
    comment: str = None,
    puser: User | None = None,
    ip_address: str | None = None,
    last_lat: str | None = None,
    last_lon: str | None = None,
) -> int | None:
    config = current_app.config["INI_CONFIG"]
    dest_component_status = config.get("Handling", "component_status")
    bool_handling = config.get("Handling", "bool_handling")

    the_components = wowi.get_components(component_id=component_id)
    if not the_components:
        logger.error(f"edit_component: Cannot find component '{component_id}'")
        return None
    the_component = the_components[0]

    component_catalog_id = the_component.component_catalog_id
    component_cat_item: ComponentCatalogItem
    component_cat_item = db.session.get(ComponentCatalogItem, component_catalog_id)

    if component_cat_item.is_bool:
        sub_components = []
    else:
        sub_components = psub_components or []

    if component_cat_item.is_bool and bool_handling == "sub_components":
        if count > 1:
            logger.error(f"edit_component comp {component_id} compcat {component_catalog_id} "
                         f"invalid count {count} for bool component!")
            return None
        if count == 1:
            sub_components.append(config.getint("Handling", "bool_sub_component_yes_id"))
        else:
            sub_components.append(config.getint("Handling", "bool_sub_component_no_id"))

    if puser is not None:
        puser.last_action = datetime.now()

    psub_string = ",".join(str(e) for e in sub_components) if sub_components else None

    new_event = None
    if puser is not None:
        new_event = EventItem(
            user_id=puser.id,
            user_name=puser.name,
            action="edit",
            ip_address=ip_address,
            last_lat=last_lat,
            last_lon=last_lon,
            use_unit_id=the_component.use_unit_id,
            facility_id=the_component.facility_id,
            facility_catalog_id=component_cat_item.facility_catalog_item_id,
            component_id=component_id,
            component_catalog_id=component_cat_item.id,
            sub_component_ids=psub_string
        )

    if unknown:
        if new_event is not None:
            new_event.action = "delete"
        wowi.delete_component(the_component.facility_id, the_component.id_)
        if new_event is not None:
            db.session.add(new_event)
        db.session.commit()
        return True

    component_subs = []
    if the_component.under_components:
        for csub in the_component.under_components:
            component_subs.append(csub.id_)

    component_subs.sort()
    sub_components.sort()

    if component_subs == sub_components and the_component.comment == comment and the_component.count == count:
        if puser is not None:
            db.session.commit()
        return True

    cr_f_result = wowi.edit_component(
        component_id=component_id,
        facility_id=the_component.facility_id,
        name=component_cat_item.name,
        count=count,
        component_catalog_id=component_cat_item.id,
        component_status_id=dest_component_status,
        under_component_ids=sub_components,
        comment=comment
    )
    _raise_for_result("edit_component", cr_f_result)
    logger.info(f"edit_component: Use Unit '{the_component.use_unit_id}' "
                f"component '{component_id}' edited. Count: {count} "
                f"facility_id: {the_component.facility_id} under_component_ids: '{str(sub_components)}' "
                f"comment '{comment}'")

    if new_event is not None:
        db.session.add(new_event)
    db.session.commit()
    return cr_f_result.data["Id"]
